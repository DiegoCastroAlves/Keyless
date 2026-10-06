-- Security hardening after the first review.
--
-- 1. Sessions must come from a password sign-in. Email-based sign-ins
--    (recovery, magic link, OTP) are refused by the access token hook and,
--    as a second layer, by every policy and RPC.
-- 2. Deletions are recoverable for 30 days and must carry a proof encrypted
--    with the vault key, so a stolen session cannot destroy data.
-- 3. Account deletion is scheduled 7 days ahead and can be cancelled.
-- 4. Sync counters are per vault: no cross-user activity leak, and writes in
--    one vault commit in counter order (no skipped rows).
-- 5. Quotas and tighter size limits.

-- ---------------------------------------------------------------------------
-- 1. Password-only sessions
-- ---------------------------------------------------------------------------

create function private.password_session() returns boolean
language sql stable set search_path = '' as $$
  select coalesce(
    (select bool_or(elem ->> 'method' = 'password')
       from jsonb_array_elements(coalesce((select auth.jwt()) -> 'amr', '[]'::jsonb)) as elem),
    false
  );
$$;
revoke all on function private.password_session() from public, anon;
grant execute on function private.password_session() to authenticated;

-- Supabase Auth "Custom Access Token" hook. Enable it in the dashboard
-- (Authentication > Hooks). Keyless accounts can only sign in with the
-- secret derived from the master password and Secret Key; email recovery or
-- magic links would give a session without either.
create function public.keyless_access_token_hook(event jsonb) returns jsonb
language plpgsql stable set search_path = '' as $$
begin
  if coalesce(event ->> 'authentication_method', '') in ('password', 'token_refresh', 'email/signup') then
    return event;
  end if;
  return jsonb_build_object(
    'error', jsonb_build_object(
      'http_code', 403,
      'message', 'Keyless accounts can only sign in with the master password and Secret Key.'
    )
  );
end;
$$;
grant usage on schema public to supabase_auth_admin;
grant execute on function public.keyless_access_token_hook(jsonb) to supabase_auth_admin;
revoke execute on function public.keyless_access_token_hook(jsonb) from authenticated, anon, public;

-- ---------------------------------------------------------------------------
-- Schema changes
-- ---------------------------------------------------------------------------

alter table public.profiles drop constraint profiles_format_check;
alter table public.profiles add constraint profiles_format_check check (format = 2);
alter table public.profiles add column delete_after timestamptz;

alter table public.vaults
  add column next_seq bigint not null default 0,
  add column item_count bigint not null default 0,
  add column deleted_at timestamptz,
  add column enc_tombstone text check (length(enc_tombstone) between 4 and 1024),
  add constraint vaults_tombstone_shape check ((deleted_at is null) = (enc_tombstone is null));

alter table public.items
  add column enc_tombstone text check (length(enc_tombstone) between 4 and 1024);
alter table public.items drop constraint items_tombstone_shape;
alter table public.items drop constraint items_enc_overview_check;
alter table public.items drop constraint items_enc_details_check;
alter table public.items
  add constraint items_enc_overview_check check (length(enc_overview) between 4 and 16384),
  add constraint items_enc_details_check check (length(enc_details) between 4 and 262144),
  -- A deleted item carries a tombstone proof; a live one carries content.
  add constraint items_tombstone_shape check ((deleted_at is null) = (enc_tombstone is null)),
  add constraint items_live_content check (deleted_at is not null or (enc_overview is not null and enc_details is not null));

-- ---------------------------------------------------------------------------
-- Server-managed columns (replaces the global sequence)
-- ---------------------------------------------------------------------------

drop trigger profiles_stamp_insert on public.profiles;
drop trigger profiles_stamp_update on public.profiles;
drop trigger vaults_stamp_insert on public.vaults;
drop trigger vaults_stamp_update on public.vaults;
drop trigger vault_members_stamp_insert on public.vault_members;
drop trigger vault_members_stamp_update on public.vault_members;
drop trigger items_stamp_insert on public.items;
drop trigger items_stamp_update on public.items;
drop function private.stamp_insert();
drop function private.stamp_update();

alter table public.vaults alter column seq drop default;
alter table public.vault_members alter column seq drop default;
alter table public.items alter column seq drop default;
drop sequence public.sync_seq;

create function private.profiles_stamp() returns trigger
language plpgsql set search_path = '' as $$
begin
  if tg_op = 'INSERT' then
    new.created_at := now();
    new.delete_after := null;
  else
    new.user_id := old.user_id;
    new.created_at := old.created_at;
  end if;
  new.updated_at := now();
  return new;
end;
$$;

create function private.vaults_stamp() returns trigger
language plpgsql set search_path = '' as $$
begin
  if tg_op = 'INSERT' then
    new.created_at := now();
    new.updated_at := now();
    new.next_seq := 1;
    new.seq := 1;
    new.item_count := 0;
    new.deleted_at := null;
    new.enc_tombstone := null;
  else
    new.id := old.id;
    new.owner_id := old.owner_id;
    new.created_at := old.created_at;
    if new.enc_meta is distinct from old.enc_meta or new.deleted_at is distinct from old.deleted_at then
      new.next_seq := new.next_seq + 1;
      new.seq := new.next_seq;
      new.updated_at := now();
    end if;
  end if;
  return new;
end;
$$;

create function private.vault_members_stamp() returns trigger
language plpgsql set search_path = '' as $$
begin
  if tg_op = 'INSERT' then
    new.created_at := now();
    new.seq := 0;
  else
    new.vault_id := old.vault_id;
    new.user_id := old.user_id;
    new.created_at := old.created_at;
  end if;
  return new;
end;
$$;

-- Runs as definer so writers (who cannot update the vault row) can still
-- advance the vault's counter. Locking the vault row serialises writes in a
-- vault, so sequence numbers commit in order.
create function private.items_stamp() returns trigger
language plpgsql security definer set search_path = '' as $$
declare
  v_seq bigint;
  v_count bigint;
begin
  if tg_op = 'INSERT' then
    update public.vaults
       set next_seq = next_seq + 1, item_count = item_count + 1
     where id = new.vault_id
     returning next_seq, item_count into v_seq, v_count;
    if v_count > 20000 then
      raise exception 'item limit reached' using errcode = '54000';
    end if;
    new.created_at := now();
    new.revision := 1;
    new.deleted_at := null;
    new.enc_tombstone := null;
  else
    if new.id <> old.id or new.vault_id <> old.vault_id then
      raise exception 'items cannot change id or vault' using errcode = '42501';
    end if;
    update public.vaults set next_seq = next_seq + 1 where id = new.vault_id returning next_seq into v_seq;
    new.created_at := old.created_at;
    new.revision := old.revision + 1;
    -- The server decides when an item was deleted.
    if new.enc_tombstone is null then
      new.deleted_at := null;
    elsif old.deleted_at is null then
      new.deleted_at := now();
    else
      new.deleted_at := old.deleted_at;
    end if;
  end if;
  new.seq := v_seq;
  new.updated_at := now();
  return new;
end;
$$;
revoke all on function private.items_stamp() from public, anon, authenticated;

create trigger profiles_stamp before insert or update on public.profiles
  for each row execute function private.profiles_stamp();
create trigger vaults_stamp before insert or update on public.vaults
  for each row execute function private.vaults_stamp();
create trigger vault_members_stamp before insert or update on public.vault_members
  for each row execute function private.vault_members_stamp();
create trigger items_stamp before insert or update on public.items
  for each row execute function private.items_stamp();

-- Writers may not touch items of a vault that is being deleted.
create or replace function private.can_write_vault(p_vault uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select coalesce(private.vault_role(p_vault) in ('owner', 'editor'), false)
     and exists (select 1 from public.vaults v where v.id = p_vault and v.deleted_at is null);
$$;

-- ---------------------------------------------------------------------------
-- Policies: same rules as before, plus a password-based session.
-- ---------------------------------------------------------------------------

drop policy "own profile: read" on public.profiles;
drop policy "own profile: create" on public.profiles;
drop policy "own profile: update" on public.profiles;
drop policy "members read vaults" on public.vaults;
drop policy "owners update vaults" on public.vaults;
drop policy "owners delete vaults" on public.vaults;
drop policy "read own memberships and members of owned vaults" on public.vault_members;
drop policy "members read items" on public.items;
drop policy "writers create items" on public.items;
drop policy "writers update items" on public.items;

create policy "own profile: read" on public.profiles
  for select to authenticated
  using (user_id = (select auth.uid()) and (select private.password_session()));
create policy "own profile: create" on public.profiles
  for insert to authenticated
  with check (user_id = (select auth.uid()) and (select private.password_session()));
create policy "own profile: update" on public.profiles
  for update to authenticated
  using (user_id = (select auth.uid()) and (select private.password_session()))
  with check (user_id = (select auth.uid()));

create policy "members read vaults" on public.vaults
  for select to authenticated
  using (private.is_vault_member(id) and (select private.password_session()));
create policy "owners update vaults" on public.vaults
  for update to authenticated
  using (private.is_vault_owner(id) and deleted_at is null and (select private.password_session()))
  with check (private.is_vault_owner(id));

create policy "read own memberships and members of owned vaults" on public.vault_members
  for select to authenticated
  using ((user_id = (select auth.uid()) or private.is_vault_owner(vault_id)) and (select private.password_session()));

create policy "members read items" on public.items
  for select to authenticated
  using (private.is_vault_member(vault_id) and (select private.password_session()));
create policy "writers create items" on public.items
  for insert to authenticated
  with check (private.can_write_vault(vault_id) and (select private.password_session()));
create policy "writers update items" on public.items
  for update to authenticated
  using (private.can_write_vault(vault_id) and (select private.password_session()))
  with check (private.can_write_vault(vault_id));

-- ---------------------------------------------------------------------------
-- Privileges
-- ---------------------------------------------------------------------------

revoke delete on public.vaults from authenticated;
revoke update on public.items from authenticated;
grant update (enc_overview, enc_details, enc_tombstone) on public.items to authenticated;

-- ---------------------------------------------------------------------------
-- RPCs
-- ---------------------------------------------------------------------------

create or replace function public.create_vault(p_id uuid, p_enc_meta text, p_enc_vault_key text)
returns public.vaults
language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := (select auth.uid());
  v_vault public.vaults;
begin
  if v_uid is null or not private.password_session() then
    raise exception 'not authenticated' using errcode = '42501';
  end if;
  if (select count(*) from public.vaults where owner_id = v_uid) >= 100 then
    raise exception 'vault limit reached' using errcode = '54000';
  end if;
  insert into public.vaults (id, owner_id, kind, enc_meta)
  values (p_id, v_uid, 'private', p_enc_meta)
  returning * into v_vault;
  insert into public.vault_members (vault_id, user_id, role, enc_vault_key)
  values (p_id, v_uid, 'owner', p_enc_vault_key);
  return v_vault;
end;
$$;

-- Marks a vault deleted. It stays readable (and restorable) for 30 days.
-- The proof is encrypted with the vault key; clients ignore deletions whose
-- proof does not decrypt and restore the vault.
create function public.delete_vault(p_id uuid, p_enc_tombstone text) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if (select auth.uid()) is null or not private.password_session() then
    raise exception 'not authenticated' using errcode = '42501';
  end if;
  if not private.is_vault_owner(p_id) then
    raise exception 'only the owner can delete a vault' using errcode = '42501';
  end if;
  if p_enc_tombstone is null or length(p_enc_tombstone) not between 4 and 1024 then
    raise exception 'invalid tombstone' using errcode = '22023';
  end if;
  update public.vaults set deleted_at = now(), enc_tombstone = p_enc_tombstone
   where id = p_id and deleted_at is null;
end;
$$;

create function public.restore_vault(p_id uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if (select auth.uid()) is null or not private.password_session() then
    raise exception 'not authenticated' using errcode = '42501';
  end if;
  if not private.is_vault_owner(p_id) then
    raise exception 'only the owner can restore a vault' using errcode = '42501';
  end if;
  update public.vaults set deleted_at = null, enc_tombstone = null where id = p_id;
end;
$$;

-- Schedules the account (and every vault it owns) for deletion in 7 days.
create or replace function public.delete_account() returns void
language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := (select auth.uid());
begin
  if v_uid is null or not private.password_session() then
    raise exception 'not authenticated' using errcode = '42501';
  end if;
  update public.profiles set delete_after = now() + interval '7 days'
   where user_id = v_uid and delete_after is null;
end;
$$;

create function public.cancel_account_deletion() returns void
language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := (select auth.uid());
begin
  if v_uid is null or not private.password_session() then
    raise exception 'not authenticated' using errcode = '42501';
  end if;
  update public.profiles set delete_after = null where user_id = v_uid;
end;
$$;

revoke all on function public.delete_vault(uuid, text) from public, anon;
revoke all on function public.restore_vault(uuid) from public, anon;
revoke all on function public.cancel_account_deletion() from public, anon;
grant execute on function public.delete_vault(uuid, text) to authenticated;
grant execute on function public.restore_vault(uuid) to authenticated;
grant execute on function public.cancel_account_deletion() to authenticated;

-- ---------------------------------------------------------------------------
-- Daily purge (pg_cron)
-- ---------------------------------------------------------------------------

create function private.purge_expired() returns void
language plpgsql security definer set search_path = '' as $$
begin
  update public.items
     set enc_overview = null, enc_details = null
   where deleted_at < now() - interval '30 days'
     and (enc_overview is not null or enc_details is not null);
  delete from public.vaults where deleted_at < now() - interval '30 days';
  delete from auth.users
   where id in (select user_id from public.profiles where delete_after < now());
end;
$$;
revoke all on function private.purge_expired() from public, anon, authenticated;

create extension if not exists pg_cron;
select cron.schedule('keyless-purge-expired', '17 3 * * *', 'select private.purge_expired()');

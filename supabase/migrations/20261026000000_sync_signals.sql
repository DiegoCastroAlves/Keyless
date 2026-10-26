-- Sync signals. When something a user syncs changes on the server (an item,
-- a vault, who is in a vault, the settings that follow the account) or a new
-- device asks to sign in to the account, the user's open devices get a
-- "sync" broadcast on their own Realtime topic, "user:<id>", and pull the
-- changes as they always do (only what changed since their cursor).
--
-- A signal carries nothing: no vault, no item, no ciphertext (Realtime adds
-- a random id). It is private: a user can join only their own topic (the
-- policy on realtime.messages below), and no client can send on it, only
-- these triggers. A signal that cannot be sent never fails the write
-- (realtime.send only warns), and devices still sync on their own.

-- The functions run as their owner: realtime.messages takes no inserts from
-- clients (it has no insert policy).
create function private.signal_users(p_users uuid[]) returns void
language plpgsql security definer set search_path = '' as $$
declare
  v_user uuid;
begin
  foreach v_user in array coalesce(p_users, '{}') loop
    perform realtime.send('{}'::jsonb, 'sync', 'user:' || v_user::text, true);
  end loop;
end;
$$;

create function private.signal_vault_members(p_vaults uuid[]) returns void
language sql security definer set search_path = '' as $$
  select private.signal_users(array(
    select distinct m.user_id from public.vault_members m where m.vault_id = any (p_vaults)
  ));
$$;

-- Items written by a statement: the members of their vaults.
create function private.signal_items() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  perform private.signal_vault_members(array(select distinct c.vault_id from changed c));
  return null;
end;
$$;

-- A vault renamed, deleted or restored: its members.
create function private.signal_vaults() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  perform private.signal_vault_members(array(select distinct c.id from changed c));
  return null;
end;
$$;

-- Someone added to a vault, removed or given another role: them and the
-- vault's other members.
create function private.signal_vault_member_changes() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  perform private.signal_users(array(
    select c.user_id from changed c
    union
    select m.user_id from public.vault_members m where m.vault_id in (select c.vault_id from changed c)
  ));
  return null;
end;
$$;

-- The account's settings, or a new device asking to sign in: the account.
create function private.signal_row_user() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  perform private.signal_users(array[new.user_id]);
  return null;
end;
$$;

revoke all on function private.signal_users(uuid[]) from public, anon, authenticated;
revoke all on function private.signal_vault_members(uuid[]) from public, anon, authenticated;
revoke all on function private.signal_items() from public, anon, authenticated;
revoke all on function private.signal_vaults() from public, anon, authenticated;
revoke all on function private.signal_vault_member_changes() from public, anon, authenticated;
revoke all on function private.signal_row_user() from public, anon, authenticated;

-- A trigger with a transition table takes a single event.
create trigger items_signal_insert after insert on public.items
  referencing new table as changed
  for each statement execute function private.signal_items();
create trigger items_signal_update after update on public.items
  referencing new table as changed
  for each statement execute function private.signal_items();

create trigger vaults_signal after update on public.vaults
  referencing new table as changed
  for each statement execute function private.signal_vaults();

create trigger vault_members_signal_insert after insert on public.vault_members
  referencing new table as changed
  for each statement execute function private.signal_vault_member_changes();
create trigger vault_members_signal_update after update on public.vault_members
  referencing new table as changed
  for each statement execute function private.signal_vault_member_changes();
create trigger vault_members_signal_delete after delete on public.vault_members
  referencing old table as changed
  for each statement execute function private.signal_vault_member_changes();

create trigger profiles_signal after update of enc_settings on public.profiles
  for each row when (old.enc_settings is distinct from new.enc_settings)
  execute function private.signal_row_user();

create trigger device_requests_signal after insert on private.device_requests
  for each row when (new.user_id is not null)
  execute function private.signal_row_user();

-- Joining "user:<id>" as a private channel: only that user.
create policy "users hear their own sync signals" on realtime.messages
  for select to authenticated
  using (
    realtime.messages.extension = 'broadcast'
    and (select realtime.topic()) = 'user:' || (select auth.uid())::text
  );

-- Keyless initial schema.
--
-- The server is zero-knowledge: every secret column holds ciphertext produced
-- on the client (XChaCha20-Poly1305 envelopes, "k1.<base64url>"). The server
-- never sees master passwords, Secret Keys or any decryption key. Row Level
-- Security limits each user to their own rows; column privileges and
-- triggers stop clients from forging server-managed columns.

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;
grant usage on schema private to authenticated;

create sequence public.sync_seq;

-- ---------------------------------------------------------------------------
-- Tables
-- ---------------------------------------------------------------------------

create table public.profiles (
  user_id uuid primary key references auth.users (id) on delete cascade,
  format smallint not null check (format = 1),
  kdf jsonb not null check (jsonb_typeof(kdf) = 'object'),
  enc_user_key text not null check (length(enc_user_key) between 4 and 512),
  public_key text not null check (length(public_key) between 4 and 128),
  enc_private_key text not null check (length(enc_private_key) between 4 and 512),
  -- Used while a master password change is in flight, so a crash between the
  -- auth update and the profile update can never lock the user out.
  pending_kdf jsonb check (pending_kdf is null or jsonb_typeof(pending_kdf) = 'object'),
  pending_enc_user_key text check (length(pending_enc_user_key) between 4 and 512),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.vaults (
  id uuid primary key,
  owner_id uuid not null references auth.users (id) on delete cascade,
  kind text not null default 'private' check (kind in ('private', 'shared')),
  enc_meta text not null check (length(enc_meta) between 4 and 16384),
  seq bigint not null default nextval('public.sync_seq'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index vaults_owner_idx on public.vaults (owner_id);

create table public.vault_members (
  vault_id uuid not null references public.vaults (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  role text not null check (role in ('owner', 'editor', 'viewer')),
  enc_vault_key text not null check (length(enc_vault_key) between 4 and 512),
  seq bigint not null default nextval('public.sync_seq'),
  created_at timestamptz not null default now(),
  primary key (vault_id, user_id)
);
create index vault_members_user_idx on public.vault_members (user_id);

create table public.items (
  id uuid primary key,
  vault_id uuid not null references public.vaults (id) on delete cascade,
  enc_overview text check (length(enc_overview) between 4 and 65536),
  enc_details text check (length(enc_details) between 4 and 1048576),
  revision integer not null default 1,
  seq bigint not null default nextval('public.sync_seq'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  -- Tombstone: a deleted item keeps its id (so other devices learn about the
  -- deletion) but loses its ciphertext.
  deleted_at timestamptz,
  constraint items_tombstone_shape check (
    (deleted_at is null and enc_overview is not null and enc_details is not null)
    or (deleted_at is not null and enc_overview is null and enc_details is null)
  )
);
create index items_vault_seq_idx on public.items (vault_id, seq);

-- ---------------------------------------------------------------------------
-- Server-managed columns
-- ---------------------------------------------------------------------------

create function private.stamp_insert() returns trigger
language plpgsql set search_path = '' as $$
begin
  new.created_at := now();
  if tg_table_name <> 'vault_members' then
    new.updated_at := now();
  end if;
  if tg_table_name <> 'profiles' then
    new.seq := nextval('public.sync_seq');
  end if;
  if tg_table_name = 'items' then
    new.revision := 1;
  end if;
  return new;
end;
$$;

create function private.stamp_update() returns trigger
language plpgsql set search_path = '' as $$
begin
  new.created_at := old.created_at;
  if tg_table_name <> 'vault_members' then
    new.updated_at := now();
  end if;
  if tg_table_name <> 'profiles' then
    new.seq := nextval('public.sync_seq');
  end if;
  if tg_table_name = 'items' then
    if new.id <> old.id or new.vault_id <> old.vault_id then
      raise exception 'items cannot change id or vault' using errcode = '42501';
    end if;
    new.revision := old.revision + 1;
  end if;
  return new;
end;
$$;

create trigger profiles_stamp_insert before insert on public.profiles
  for each row execute function private.stamp_insert();
create trigger profiles_stamp_update before update on public.profiles
  for each row execute function private.stamp_update();
create trigger vaults_stamp_insert before insert on public.vaults
  for each row execute function private.stamp_insert();
create trigger vaults_stamp_update before update on public.vaults
  for each row execute function private.stamp_update();
create trigger vault_members_stamp_insert before insert on public.vault_members
  for each row execute function private.stamp_insert();
create trigger vault_members_stamp_update before update on public.vault_members
  for each row execute function private.stamp_update();
create trigger items_stamp_insert before insert on public.items
  for each row execute function private.stamp_insert();
create trigger items_stamp_update before update on public.items
  for each row execute function private.stamp_update();

-- ---------------------------------------------------------------------------
-- Access helpers (private schema: not exposed through the Data API)
-- ---------------------------------------------------------------------------

create function private.vault_role(p_vault uuid) returns text
language sql stable security definer set search_path = '' as $$
  select m.role from public.vault_members m
  where m.vault_id = p_vault and m.user_id = (select auth.uid());
$$;

create function private.is_vault_member(p_vault uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select private.vault_role(p_vault) is not null;
$$;

create function private.can_write_vault(p_vault uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select coalesce(private.vault_role(p_vault) in ('owner', 'editor'), false);
$$;

create function private.is_vault_owner(p_vault uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select coalesce(private.vault_role(p_vault) = 'owner', false);
$$;

revoke all on all functions in schema private from public, anon;
grant execute on function private.vault_role(uuid) to authenticated;
grant execute on function private.is_vault_member(uuid) to authenticated;
grant execute on function private.can_write_vault(uuid) to authenticated;
grant execute on function private.is_vault_owner(uuid) to authenticated;

-- ---------------------------------------------------------------------------
-- Row Level Security
-- ---------------------------------------------------------------------------

alter table public.profiles enable row level security;
alter table public.vaults enable row level security;
alter table public.vault_members enable row level security;
alter table public.items enable row level security;

create policy "own profile: read" on public.profiles
  for select to authenticated using (user_id = (select auth.uid()));
create policy "own profile: create" on public.profiles
  for insert to authenticated with check (user_id = (select auth.uid()));
create policy "own profile: update" on public.profiles
  for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

create policy "members read vaults" on public.vaults
  for select to authenticated using (private.is_vault_member(id));
create policy "owners update vaults" on public.vaults
  for update to authenticated
  using (private.is_vault_owner(id))
  with check (private.is_vault_owner(id));
create policy "owners delete vaults" on public.vaults
  for delete to authenticated using (private.is_vault_owner(id));

create policy "read own memberships and members of owned vaults" on public.vault_members
  for select to authenticated
  using (user_id = (select auth.uid()) or private.is_vault_owner(vault_id));

create policy "members read items" on public.items
  for select to authenticated using (private.is_vault_member(vault_id));
create policy "writers create items" on public.items
  for insert to authenticated with check (private.can_write_vault(vault_id));
create policy "writers update items" on public.items
  for update to authenticated
  using (private.can_write_vault(vault_id))
  with check (private.can_write_vault(vault_id));

-- ---------------------------------------------------------------------------
-- Privileges: nothing for anon; column-level writes for authenticated.
-- ---------------------------------------------------------------------------

revoke all on public.profiles, public.vaults, public.vault_members, public.items from anon, authenticated;
revoke all on sequence public.sync_seq from anon, authenticated;
-- Column defaults and the stamp triggers call nextval() as the invoking role.
grant usage on sequence public.sync_seq to authenticated;

grant select on public.profiles, public.vaults, public.vault_members, public.items to authenticated;
grant insert (user_id, format, kdf, enc_user_key, public_key, enc_private_key) on public.profiles to authenticated;
grant update (format, kdf, enc_user_key, enc_private_key, pending_kdf, pending_enc_user_key) on public.profiles to authenticated;
grant update (enc_meta) on public.vaults to authenticated;
grant delete on public.vaults to authenticated;
grant insert (id, vault_id, enc_overview, enc_details) on public.items to authenticated;
grant update (enc_overview, enc_details, deleted_at) on public.items to authenticated;

-- ---------------------------------------------------------------------------
-- RPCs
-- ---------------------------------------------------------------------------

-- Creates a vault and the caller's owner membership atomically.
create function public.create_vault(p_id uuid, p_enc_meta text, p_enc_vault_key text)
returns public.vaults
language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := (select auth.uid());
  v_vault public.vaults;
begin
  if v_uid is null then
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

-- Deletes the caller's account and, by cascade, every vault they own.
create function public.delete_account() returns void
language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := (select auth.uid());
begin
  if v_uid is null then
    raise exception 'not authenticated' using errcode = '42501';
  end if;
  delete from public.vaults where owner_id = v_uid;
  delete from auth.users where id = v_uid;
end;
$$;

revoke all on function public.create_vault(uuid, text, text) from public, anon;
revoke all on function public.delete_account() from public, anon;
grant execute on function public.create_vault(uuid, text, text) to authenticated;
grant execute on function public.delete_account() to authenticated;

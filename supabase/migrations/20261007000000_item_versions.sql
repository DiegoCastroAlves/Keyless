-- Earlier versions of items, for the item history ("restore a previous
-- version", like 1Password).
--
-- Only a trigger writes here: when a client replaces an item's content, the
-- ciphertext it replaced is kept as is. The server can neither read nor
-- forge a version (each is encrypted and bound to its vault and item), and
-- restoring one writes its content as a new version, so the clients'
-- rollback protection is unchanged.
--
-- The newest 30 versions of an item are kept, for at most a year, and go
-- away with the item.

create table public.item_versions (
  item_id uuid not null references public.items (id) on delete cascade,
  vault_id uuid not null references public.vaults (id) on delete cascade,
  -- The server's revision of the item when this content was current.
  revision integer not null,
  enc_overview text not null,
  enc_details text not null,
  -- When this content was written, and when it was replaced.
  written_at timestamptz not null,
  replaced_at timestamptz not null default now(),
  primary key (item_id, revision)
);
create index item_versions_vault_idx on public.item_versions (vault_id);

alter table public.item_versions enable row level security;

create policy "members read item versions" on public.item_versions
  for select to authenticated
  using (private.is_vault_member(vault_id) and (select private.password_session()));

revoke all on public.item_versions from anon, authenticated;
grant select on public.item_versions to authenticated;

create function private.items_keep_version() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  -- Content that changed, of an item that was not deleted.
  if old.deleted_at is null
     and old.enc_overview is not null and old.enc_details is not null
     and (new.enc_overview is distinct from old.enc_overview
          or new.enc_details is distinct from old.enc_details) then
    insert into public.item_versions (item_id, vault_id, revision, enc_overview, enc_details, written_at)
    values (old.id, old.vault_id, old.revision, old.enc_overview, old.enc_details, old.updated_at)
    on conflict (item_id, revision) do nothing;
    delete from public.item_versions
     where item_id = old.id
       and revision not in (
         select v.revision from public.item_versions v
          where v.item_id = old.id
          order by v.revision desc
          limit 30);
  end if;
  return null;
end;
$$;
revoke all on function private.items_keep_version() from public, anon, authenticated;

create trigger items_keep_version after update on public.items
  for each row execute function private.items_keep_version();

-- The daily purge also drops versions older than a year, and those of items
-- deleted for good.
create or replace function private.purge_expired() returns void
language plpgsql security definer set search_path = '' as $$
begin
  update public.items
     set enc_overview = null, enc_details = null
   where deleted_at < now() - interval '30 days'
     and (enc_overview is not null or enc_details is not null);
  delete from public.item_versions v
   using public.items i
   where v.item_id = i.id and i.deleted_at < now() - interval '30 days';
  delete from public.item_versions where replaced_at < now() - interval '365 days';
  delete from public.vaults where deleted_at < now() - interval '30 days';
  delete from auth.users
   where id in (select user_id from public.profiles where delete_after < now());
end;
$$;
revoke all on function private.purge_expired() from public, anon, authenticated;

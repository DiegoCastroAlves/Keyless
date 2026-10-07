-- File attachments in items, like 1Password's.
--
-- Files are encrypted on the device, in chunks of 4 MiB, with a random key
-- per file that is kept in the item's encrypted details. The server stores
-- only ciphertext, as private objects named
-- <vault id>/<attachment id>/<chunk number>.
--
-- Members of the vault may read them and writers may add and remove them.
-- Whoever uploaded an object may also read and remove it after leaving the
-- vault or once the vault is gone for good, so nothing is stranded. Objects
-- are never replaced.
--
-- Each account may keep up to 250 MiB of its own uploads. The limit lives
-- only here, so it can change without a new app.

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('attachments', 'attachments', false, 4194344, array['application/octet-stream']);

-- 250 MiB per account.
create function private.attachment_quota() returns bigint
language sql immutable set search_path = '' as $$
  select 262144000::bigint;
$$;

-- The vault an attachment object belongs to, from its name; null for any
-- other name, which no policy accepts.
create function private.attachment_vault(p_name text) returns uuid
language sql immutable set search_path = '' as $$
  select case
    when p_name ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/(0|[1-9][0-9]{0,4})$'
    then split_part(p_name, '/', 1)::uuid
  end;
$$;

-- Bytes of attachments the signed-in account uploaded.
create function private.attachment_usage() returns bigint
language sql stable security definer set search_path = '' as $$
  select coalesce(sum((o.metadata ->> 'size')::bigint), 0)::bigint
    from storage.objects o
   where o.bucket_id = 'attachments'
     and o.owner_id = (select auth.uid())::text;
$$;

revoke all on function private.attachment_quota() from public, anon;
revoke all on function private.attachment_vault(text) from public, anon;
revoke all on function private.attachment_usage() from public, anon;
grant execute on function private.attachment_quota() to authenticated;
grant execute on function private.attachment_vault(text) to authenticated;
grant execute on function private.attachment_usage() to authenticated;

create policy "members read attachments" on storage.objects
  for select to authenticated
  using (
    bucket_id = 'attachments'
    and (select private.password_session())
    and (private.is_vault_member(private.attachment_vault(name)) or owner_id = (select auth.uid())::text)
  );

-- Room is checked for a whole chunk: the new object's size is not known yet.
create policy "writers add attachments" on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'attachments'
    and (select private.password_session())
    and private.can_write_vault(private.attachment_vault(name))
    and (select private.attachment_usage()) + 4194344 <= (select private.attachment_quota())
  );

create policy "writers and uploaders remove attachments" on storage.objects
  for delete to authenticated
  using (
    bucket_id = 'attachments'
    and (select private.password_session())
    and (private.can_write_vault(private.attachment_vault(name)) or owner_id = (select auth.uid())::text)
  );

-- How much attachment space the account uses, and how much it has.
create function public.attachment_space() returns jsonb
language sql stable security definer set search_path = '' as $$
  select jsonb_build_object('used', private.attachment_usage(), 'quota', private.attachment_quota())
   where (select private.password_session());
$$;

-- Objects the account uploaded to vaults it no longer belongs to (left, or
-- deleted for good): the app removes them.
create function public.stranded_attachments() returns setof text
language sql stable security definer set search_path = '' as $$
  select o.name
    from storage.objects o
   where o.bucket_id = 'attachments'
     and o.owner_id = (select auth.uid())::text
     and (select private.password_session())
     and not coalesce(private.is_vault_member(private.attachment_vault(o.name)), false)
   order by o.name
   limit 1000;
$$;

revoke all on function public.attachment_space() from public, anon;
revoke all on function public.stranded_attachments() from public, anon;
grant execute on function public.attachment_space() to authenticated;
grant execute on function public.stranded_attachments() to authenticated;

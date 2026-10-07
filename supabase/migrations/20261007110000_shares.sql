-- Share links: a copy of an item for someone without Keyless, like
-- 1Password's "share item".
--
-- The app encrypts a snapshot of the item with a random key that goes only
-- in the link's fragment (after '#', which browsers never send), so the
-- server keeps ciphertext it cannot read. Anyone with the link can open it
-- through open_share() until it expires (30 days at most), is revoked, or
-- has been viewed as many times as allowed. The owner also keeps a label
-- encrypted with their own key, to list and revoke their links.

create table public.shares (
  id uuid primary key,
  owner_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
  enc_payload text not null check (length(enc_payload) between 4 and 131072),
  enc_label text not null check (length(enc_label) between 4 and 4096),
  expires_at timestamptz not null,
  -- null: any number of views.
  max_views integer check (max_views between 1 and 100),
  views integer not null default 0,
  created_at timestamptz not null default now(),
  revoked_at timestamptz
);
create index shares_owner_idx on public.shares (owner_id);

alter table public.shares enable row level security;

-- Active links an account may have at once.
create function private.share_room() returns boolean
language sql stable security definer set search_path = '' as $$
  select count(*) < 100 from public.shares s
   where s.owner_id = (select auth.uid()) and s.revoked_at is null and s.expires_at > now();
$$;
revoke all on function private.share_room() from public, anon;
grant execute on function private.share_room() to authenticated;

create policy "owners read their shares" on public.shares
  for select to authenticated
  using (owner_id = (select auth.uid()) and (select private.password_session()));

create policy "owners create shares" on public.shares
  for insert to authenticated
  with check (
    owner_id = (select auth.uid())
    and (select private.password_session())
    and views = 0
    and revoked_at is null
    and expires_at > now()
    and expires_at <= now() + interval '30 days 5 minutes'
    and (select private.share_room())
  );

create policy "owners revoke shares" on public.shares
  for update to authenticated
  using (owner_id = (select auth.uid()) and (select private.password_session()))
  with check (owner_id = (select auth.uid()) and revoked_at is not null);

revoke all on public.shares from anon, authenticated;
grant select (id, enc_label, expires_at, max_views, views, created_at, revoked_at) on public.shares to authenticated;
grant insert (id, enc_payload, enc_label, expires_at, max_views) on public.shares to authenticated;
grant update (revoked_at) on public.shares to authenticated;

-- Opens a link: its ciphertext, counting the view. Nothing for a link that
-- does not exist, expired, was revoked or was viewed enough times.
create function public.open_share(p_id uuid) returns jsonb
language sql volatile security definer set search_path = '' as $$
  update public.shares s
     set views = s.views + 1
   where s.id = p_id
     and s.revoked_at is null
     and s.expires_at > now()
     and (s.max_views is null or s.views < s.max_views)
  returning jsonb_build_object(
    'payload', s.enc_payload,
    'expiresAt', s.expires_at,
    'viewsLeft', case when s.max_views is null then null else s.max_views - s.views end
  );
$$;
revoke all on function public.open_share(uuid) from public;
grant execute on function public.open_share(uuid) to anon, authenticated;

-- The daily purge also drops links a day after they ended.
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
  delete from public.shares
   where expires_at < now() - interval '1 day'
      or revoked_at < now() - interval '1 day'
      or (max_views is not null and views >= max_views and created_at < now() - interval '1 day');
  delete from public.vaults where deleted_at < now() - interval '30 days';
  delete from auth.users
   where id in (select user_id from public.profiles where delete_after < now());
end;
$$;
revoke all on function private.purge_expired() from public, anon, authenticated;

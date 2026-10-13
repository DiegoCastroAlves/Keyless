-- The account's devices: each signed-in app registers itself, so the user
-- can see where the account is open (name, system, address, country, last
-- seen) and sign a device out from another one.
--
-- A device is tied to its Supabase Auth session. Signing it out ends that
-- session, which stops its access token at once: private.password_session()
-- now also requires the session to still exist. The signed-out device then
-- learns (device_status, with a secret only it knows) that it was signed out
-- and removes the account's data it keeps.
--
-- The device's name, system and app version are encrypted with the user key;
-- the server only sees the address and country of its requests, as it
-- already does.

create table public.devices (
  id uuid primary key,
  user_id uuid not null references auth.users (id) on delete cascade,
  session_id uuid,
  secret_hash bytea not null,
  enc_info text not null check (length(enc_info) between 4 and 2048),
  ip text check (length(ip) <= 45),
  country text check (country ~ '^[A-Z]{2}$'),
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  revoked_at timestamptz
);
create index devices_user_idx on public.devices (user_id);

alter table public.devices enable row level security;
create policy "own devices: read" on public.devices
  for select to authenticated
  using (user_id = (select auth.uid()) and (select private.password_session()));

revoke all on public.devices from anon, authenticated;
-- Never the session or the secret's hash. Writes go through the functions below.
grant select (id, enc_info, ip, country, created_at, last_seen_at, revoked_at) on public.devices to authenticated;

-- ---------------------------------------------------------------------------
-- Sessions that were signed out stop at once
-- ---------------------------------------------------------------------------

create or replace function private.password_session() returns boolean
language sql stable security definer set search_path = '' as $$
  select coalesce(
    (select bool_or(elem ->> 'method' = 'password')
       from jsonb_array_elements(coalesce((select auth.jwt()) -> 'amr', '[]'::jsonb)) as elem),
    false
  ) and (
    (select auth.jwt()) ->> 'session_id' is null
    or exists (select 1 from auth.sessions s where s.id = ((select auth.jwt()) ->> 'session_id')::uuid)
  );
$$;
revoke all on function private.password_session() from public, anon;
grant execute on function private.password_session() to authenticated;

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

-- Where the current request comes from: the client's address and, when the
-- CDN in front of the API says so, its country.
create function private.request_origin(out ip text, out country text)
language plpgsql stable set search_path = '' as $$
declare
  v_headers jsonb;
  v_candidate text;
begin
  begin
    v_headers := coalesce(nullif(current_setting('request.headers', true), '')::jsonb, '{}'::jsonb);
  exception when others then
    v_headers := '{}'::jsonb;
  end;
  foreach v_candidate in array array[
    v_headers ->> 'cf-connecting-ip',
    v_headers ->> 'x-real-ip',
    trim(split_part(coalesce(v_headers ->> 'x-forwarded-for', ''), ',', 1))
  ] loop
    begin
      if nullif(v_candidate, '') is not null then
        ip := host(v_candidate::inet);
        exit;
      end if;
    exception when others then
      null;
    end;
  end loop;
  country := upper(coalesce(v_headers ->> 'cf-ipcountry', ''));
  if country !~ '^[A-Z]{2}$' or country in ('XX', 'T1') then
    country := null;
  end if;
end;
$$;
revoke all on function private.request_origin() from public, anon, authenticated;

create function private.current_session() returns uuid
language sql stable set search_path = '' as $$
  select nullif((select auth.jwt()) ->> 'session_id', '')::uuid;
$$;
revoke all on function private.current_session() from public, anon, authenticated;

create function private.end_session(p_session uuid) returns void
language sql volatile security definer set search_path = '' as $$
  delete from auth.refresh_tokens where session_id = p_session;
  delete from auth.sessions where id = p_session;
$$;
revoke all on function private.end_session(uuid) from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- RPCs
-- ---------------------------------------------------------------------------

-- Registers the calling device (after each sign-in), or updates it.
create function public.register_device(p_id uuid, p_secret text, p_enc_info text) returns void
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_uid uuid := (select auth.uid());
  v_session uuid := private.current_session();
  v_origin record;
  v_old public.devices;
begin
  if v_uid is null or not private.password_session() then
    raise exception 'a password session is required' using errcode = '42501';
  end if;
  if length(coalesce(p_secret, '')) <> 43 or length(coalesce(p_enc_info, '')) not between 4 and 2048 then
    raise exception 'invalid device' using errcode = '22023';
  end if;
  select * into v_origin from private.request_origin();
  select * into v_old from public.devices where id = p_id for update;
  if found then
    if v_old.user_id <> v_uid then
      raise exception 'invalid device' using errcode = '42501';
    end if;
    -- A new sign-in on the device replaces its previous session.
    if v_old.session_id is not null and v_old.session_id is distinct from v_session then
      perform private.end_session(v_old.session_id);
    end if;
    update public.devices
       set session_id = v_session,
           secret_hash = extensions.digest(p_secret, 'sha256'),
           enc_info = p_enc_info,
           ip = v_origin.ip,
           country = v_origin.country,
           last_seen_at = now(),
           revoked_at = null
     where id = p_id;
  else
    if (select count(*) from public.devices where user_id = v_uid and revoked_at is null) >= 50 then
      raise exception 'device limit reached' using errcode = '54000';
    end if;
    insert into public.devices (id, user_id, session_id, secret_hash, enc_info, ip, country)
    values (p_id, v_uid, v_session, extensions.digest(p_secret, 'sha256'), p_enc_info, v_origin.ip, v_origin.country);
  end if;
end;
$$;

-- Called now and then by a signed-in device: 'active', or 'unknown' when it
-- has to register (again).
create function public.device_seen(p_id uuid) returns text
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_uid uuid := (select auth.uid());
  v_origin record;
begin
  if v_uid is null or not private.password_session() then
    raise exception 'a password session is required' using errcode = '42501';
  end if;
  select * into v_origin from private.request_origin();
  update public.devices
     set last_seen_at = now(),
         ip = coalesce(v_origin.ip, ip),
         country = coalesce(v_origin.country, country),
         session_id = coalesce(private.current_session(), session_id)
   where id = p_id and user_id = v_uid and revoked_at is null;
  return case when found then 'active' else 'unknown' end;
end;
$$;

-- For a device whose session stopped working: 'revoked' when it was signed
-- out from another device, 'active' or 'unknown' otherwise. Only the device
-- knows its secret.
create function public.device_status(p_id uuid, p_secret text) returns text
language sql stable security definer set search_path = '' as $$
  select coalesce(
    (select case when d.revoked_at is null then 'active' else 'revoked' end
       from public.devices d
      where d.id = p_id and d.secret_hash = extensions.digest(coalesce(p_secret, ''), 'sha256')),
    'unknown'
  );
$$;

-- Signs another device of the account out.
create function public.revoke_device(p_id uuid) returns void
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_uid uuid := (select auth.uid());
  v_device public.devices;
begin
  if v_uid is null or not private.password_session() then
    raise exception 'a password session is required' using errcode = '42501';
  end if;
  select * into v_device from public.devices where id = p_id and user_id = v_uid for update;
  if not found then
    raise exception 'device not found' using errcode = 'P0002';
  end if;
  if v_device.session_id is not distinct from private.current_session() then
    raise exception 'this is the current device' using errcode = '22023';
  end if;
  if v_device.session_id is not null then
    perform private.end_session(v_device.session_id);
  end if;
  update public.devices set revoked_at = now(), session_id = null where id = p_id;
end;
$$;

-- The calling device is signing out: it leaves the list.
create function public.remove_device(p_id uuid) returns void
language plpgsql volatile security definer set search_path = '' as $$
begin
  if (select auth.uid()) is null or not private.password_session() then
    raise exception 'a password session is required' using errcode = '42501';
  end if;
  delete from public.devices
   where id = p_id
     and user_id = (select auth.uid())
     and (session_id is not distinct from private.current_session() or revoked_at is not null);
end;
$$;

revoke all on function public.register_device(uuid, text, text) from public, anon;
revoke all on function public.device_seen(uuid) from public, anon;
revoke all on function public.device_status(uuid, text) from public;
revoke all on function public.revoke_device(uuid) from public, anon;
revoke all on function public.remove_device(uuid) from public, anon;
grant execute on function public.register_device(uuid, text, text) to authenticated;
grant execute on function public.device_seen(uuid) to authenticated;
grant execute on function public.device_status(uuid, text) to anon, authenticated;
grant execute on function public.revoke_device(uuid) to authenticated;
grant execute on function public.remove_device(uuid) to authenticated;

-- ---------------------------------------------------------------------------
-- Daily purge: signed-out devices after 90 days, and devices whose session
-- is gone and that were not seen for 180 days.
-- ---------------------------------------------------------------------------

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
  delete from public.devices
   where revoked_at < now() - interval '90 days'
      or (last_seen_at < now() - interval '180 days'
          and (session_id is null or not exists (select 1 from auth.sessions s where s.id = devices.session_id)));
  delete from auth.users
   where id in (select user_id from public.profiles where delete_after < now());
end;
$$;
revoke all on function private.purge_expired() from public, anon, authenticated;

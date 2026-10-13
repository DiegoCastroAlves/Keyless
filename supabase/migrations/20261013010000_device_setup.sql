-- Signing in on a new device with the help of a signed-in one (see
-- keyless_core::device_setup). The new device leaves a request for the
-- account's email; a signed-in device answers it, the new device reveals its
-- nonce, the user types on the signed-in device the code the new one shows,
-- and the signed-in device leaves the email and Secret Key encrypted for the
-- new device's key. The master password is still typed on the new device.
--
-- The server only relays public keys, nonces and one ciphertext it cannot
-- read. Anyone may leave a request (the new device has no session), so they
-- are limited: 3 waiting and 10 an hour per account, 20 an hour per address;
-- a request expires after 10 minutes and an unknown email gets a request no
-- device will ever see, which looks the same to the asker.

create table private.device_requests (
  id uuid primary key,
  user_id uuid references auth.users (id) on delete cascade,
  secret_hash bytea not null,
  public_key text not null check (length(public_key) = 43),
  commitment text not null check (length(commitment) = 43),
  platform text not null check (platform in ('linux', 'windows', 'macos', 'android', 'ios', 'web')),
  ip text,
  country text,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '10 minutes',
  status text not null default 'pending' check (status in ('pending', 'answered', 'revealed', 'approved', 'denied')),
  approver_session uuid,
  approver_key text check (length(approver_key) = 43),
  approver_nonce text check (length(approver_nonce) = 22),
  nonce text check (length(nonce) = 22),
  enc_payload text check (length(enc_payload) between 4 and 4096)
);
create index device_requests_user_idx on private.device_requests (user_id, created_at);
create index device_requests_ip_idx on private.device_requests (ip, created_at);
alter table private.device_requests enable row level security;

-- New device: leaves a request. Returns {"ok": true} or {"error": "device_setup_throttled"}.
create function public.request_device_setup(
  p_email text,
  p_id uuid,
  p_secret text,
  p_public_key text,
  p_commitment text,
  p_platform text
) returns jsonb
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_user uuid;
  v_origin record;
begin
  if length(coalesce(p_secret, '')) <> 43
     or length(coalesce(p_public_key, '')) <> 43
     or length(coalesce(p_commitment, '')) <> 43
     or p_platform not in ('linux', 'windows', 'macos', 'android', 'ios', 'web') then
    return jsonb_build_object('error', 'invalid_request');
  end if;
  select * into v_origin from private.request_origin();
  select u.id into v_user
    from auth.users u
   where lower(u.email) = lower(trim(coalesce(p_email, '')))
     and u.deleted_at is null
     and exists (select 1 from public.profiles p where p.user_id = u.id);
  if (v_origin.ip is not null
      and (select count(*) from private.device_requests r
            where r.ip = v_origin.ip and r.created_at > now() - interval '1 hour') >= 20)
     or (v_user is not null
      and ((select count(*) from private.device_requests r
             where r.user_id = v_user and r.created_at > now() - interval '1 hour') >= 10
        or (select count(*) from private.device_requests r
             where r.user_id = v_user and r.expires_at > now()
               and r.status in ('pending', 'answered', 'revealed')) >= 3)) then
    return jsonb_build_object('error', 'device_setup_throttled');
  end if;
  insert into private.device_requests (id, user_id, secret_hash, public_key, commitment, platform, ip, country)
  values (p_id, v_user, extensions.digest(p_secret, 'sha256'), p_public_key, p_commitment, p_platform, v_origin.ip, v_origin.country);
  return jsonb_build_object('ok', true);
exception when unique_violation then
  return jsonb_build_object('error', 'invalid_request');
end;
$$;

-- New device: where its request is. Once approved, the encrypted payload is
-- handed out once and the request deleted.
create function public.device_setup_status(p_id uuid, p_secret text) returns jsonb
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_request private.device_requests;
begin
  select * into v_request
    from private.device_requests r
   where r.id = p_id and r.secret_hash = extensions.digest(coalesce(p_secret, ''), 'sha256')
   for update;
  if not found then
    return jsonb_build_object('status', 'unknown');
  end if;
  if v_request.status = 'approved' then
    delete from private.device_requests where id = p_id;
    return jsonb_build_object(
      'status', 'approved',
      'approver_key', v_request.approver_key,
      'approver_nonce', v_request.approver_nonce,
      'payload', v_request.enc_payload
    );
  end if;
  if v_request.expires_at <= now() then
    return jsonb_build_object('status', 'expired');
  end if;
  return jsonb_build_object(
    'status', v_request.status,
    'approver_key', v_request.approver_key,
    'approver_nonce', v_request.approver_nonce
  );
end;
$$;

-- New device: reveals its nonce once a device answered.
create function public.reveal_device_setup(p_id uuid, p_secret text, p_nonce text) returns boolean
language plpgsql volatile security definer set search_path = '' as $$
begin
  if length(coalesce(p_nonce, '')) <> 22 then
    return false;
  end if;
  update private.device_requests
     set nonce = p_nonce, status = 'revealed'
   where id = p_id
     and secret_hash = extensions.digest(coalesce(p_secret, ''), 'sha256')
     and status = 'answered'
     and expires_at > now();
  return found;
end;
$$;

-- New device: gives up.
create function public.cancel_device_setup(p_id uuid, p_secret text) returns void
language sql volatile security definer set search_path = '' as $$
  delete from private.device_requests
   where id = p_id and secret_hash = extensions.digest(coalesce(p_secret, ''), 'sha256');
$$;

-- Signed-in devices: the account's requests still waiting.
create function public.pending_device_setups() returns jsonb
language plpgsql stable security definer set search_path = '' as $$
declare
  v_session uuid := private.current_session();
begin
  if (select auth.uid()) is null or not private.password_session() then
    raise exception 'a password session is required' using errcode = '42501';
  end if;
  return coalesce((
    select jsonb_agg(jsonb_build_object(
      'id', r.id,
      'public_key', r.public_key,
      'commitment', r.commitment,
      'platform', r.platform,
      'ip', r.ip,
      'country', r.country,
      'created_at', r.created_at,
      'expires_at', r.expires_at,
      'status', r.status,
      'nonce', r.nonce,
      'mine', r.approver_session is not distinct from v_session and r.approver_session is not null
    ) order by r.created_at)
      from private.device_requests r
     where r.user_id = (select auth.uid())
       and r.expires_at > now()
       and r.status in ('pending', 'answered', 'revealed')
  ), '[]'::jsonb);
end;
$$;

-- Signed-in device: answers a waiting request with its key and nonce. The
-- first device to answer is the one that can approve.
create function public.answer_device_setup(p_id uuid, p_public_key text, p_nonce text) returns boolean
language plpgsql volatile security definer set search_path = '' as $$
begin
  if (select auth.uid()) is null or not private.password_session() then
    raise exception 'a password session is required' using errcode = '42501';
  end if;
  if length(coalesce(p_public_key, '')) <> 43 or length(coalesce(p_nonce, '')) <> 22 then
    return false;
  end if;
  update private.device_requests
     set approver_session = private.current_session(),
         approver_key = p_public_key,
         approver_nonce = p_nonce,
         status = 'answered'
   where id = p_id
     and user_id = (select auth.uid())
     and status = 'pending'
     and expires_at > now();
  return found;
end;
$$;

-- Signed-in device: after the user typed the right code, leaves the payload.
create function public.approve_device_setup(p_id uuid, p_enc_payload text) returns boolean
language plpgsql volatile security definer set search_path = '' as $$
begin
  if (select auth.uid()) is null or not private.password_session() then
    raise exception 'a password session is required' using errcode = '42501';
  end if;
  if length(coalesce(p_enc_payload, '')) not between 4 and 4096 then
    return false;
  end if;
  update private.device_requests
     set enc_payload = p_enc_payload, status = 'approved'
   where id = p_id
     and user_id = (select auth.uid())
     and status = 'revealed'
     and approver_session = private.current_session()
     and expires_at > now();
  return found;
end;
$$;

-- Signed-in device: refuses a request.
create function public.deny_device_setup(p_id uuid) returns void
language plpgsql volatile security definer set search_path = '' as $$
begin
  if (select auth.uid()) is null or not private.password_session() then
    raise exception 'a password session is required' using errcode = '42501';
  end if;
  update private.device_requests
     set status = 'denied', enc_payload = null
   where id = p_id
     and user_id = (select auth.uid())
     and status in ('pending', 'answered', 'revealed');
end;
$$;

revoke all on function public.request_device_setup(text, uuid, text, text, text, text) from public;
revoke all on function public.device_setup_status(uuid, text) from public;
revoke all on function public.reveal_device_setup(uuid, text, text) from public;
revoke all on function public.cancel_device_setup(uuid, text) from public;
revoke all on function public.pending_device_setups() from public, anon;
revoke all on function public.answer_device_setup(uuid, text, text) from public, anon;
revoke all on function public.approve_device_setup(uuid, text) from public, anon;
revoke all on function public.deny_device_setup(uuid) from public, anon;
grant execute on function public.request_device_setup(text, uuid, text, text, text, text) to anon, authenticated;
grant execute on function public.device_setup_status(uuid, text) to anon, authenticated;
grant execute on function public.reveal_device_setup(uuid, text, text) to anon, authenticated;
grant execute on function public.cancel_device_setup(uuid, text) to anon, authenticated;
grant execute on function public.pending_device_setups() to authenticated;
grant execute on function public.answer_device_setup(uuid, text, text) to authenticated;
grant execute on function public.approve_device_setup(uuid, text) to authenticated;
grant execute on function public.deny_device_setup(uuid) to authenticated;

-- Requests are kept a day (for the hourly limits), then dropped.
create function private.purge_device_requests() returns void
language sql volatile security definer set search_path = '' as $$
  delete from private.device_requests where created_at < now() - interval '1 day';
$$;
revoke all on function private.purge_device_requests() from public, anon, authenticated;
select cron.schedule('keyless-purge-device-requests', '23 * * * *', 'select private.purge_device_requests()');

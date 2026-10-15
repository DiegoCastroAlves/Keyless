-- Signing in on a new device by scanning its QR code with a signed-in phone
-- (see keyless_core::qr_sign_in). The new device leaves a request with only
-- an id, a secret to ask with, and its platform; its QR code holds the id,
-- its public key and a token the server never sees. The phone that reads it
-- leaves its own public key and the email and Secret Key sealed for the new
-- device, which takes them once. The master password is still typed on the
-- new device.
--
-- Anyone may leave a request (the new device has no session), so they are
-- limited to 20 an hour per address; a request lasts 10 minutes and belongs
-- to no account until a signed-in device answers it.

create table private.qr_sign_ins (
  id uuid primary key,
  secret_hash bytea not null,
  platform text not null check (platform in ('linux', 'windows', 'macos', 'android', 'ios', 'web')),
  ip text,
  country text,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '10 minutes',
  status text not null default 'waiting' check (status in ('waiting', 'approved', 'denied')),
  user_id uuid references auth.users (id) on delete cascade,
  approver_key text check (length(approver_key) = 43),
  enc_payload text check (length(enc_payload) between 4 and 4096)
);
create index qr_sign_ins_ip_idx on private.qr_sign_ins (ip, created_at);
alter table private.qr_sign_ins enable row level security;

-- New device: leaves a request. Returns {"ok": true} or {"error": "qr_sign_in_throttled"}.
create function public.start_qr_sign_in(p_id uuid, p_secret text, p_platform text) returns jsonb
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_origin record;
begin
  if p_id is null
     or length(coalesce(p_secret, '')) <> 43
     or p_platform is null
     or p_platform not in ('linux', 'windows', 'macos', 'android', 'ios', 'web') then
    return jsonb_build_object('error', 'invalid_request');
  end if;
  select * into v_origin from private.request_origin();
  if v_origin.ip is not null
     and (select count(*) from private.qr_sign_ins r
           where r.ip = v_origin.ip and r.created_at > now() - interval '1 hour') >= 20 then
    return jsonb_build_object('error', 'qr_sign_in_throttled');
  end if;
  insert into private.qr_sign_ins (id, secret_hash, platform, ip, country)
  values (p_id, extensions.digest(p_secret, 'sha256'), p_platform, v_origin.ip, v_origin.country);
  return jsonb_build_object('ok', true);
exception when unique_violation then
  return jsonb_build_object('error', 'invalid_request');
end;
$$;

-- New device: where its request is. Once approved, the answer is handed out
-- once and the request deleted.
create function public.qr_sign_in_status(p_id uuid, p_secret text) returns jsonb
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_request private.qr_sign_ins;
begin
  select * into v_request
    from private.qr_sign_ins r
   where r.id = p_id and r.secret_hash = extensions.digest(coalesce(p_secret, ''), 'sha256')
   for update;
  if not found then
    return jsonb_build_object('status', 'unknown');
  end if;
  if v_request.status = 'approved' then
    delete from private.qr_sign_ins where id = p_id;
    return jsonb_build_object('status', 'approved', 'approver_key', v_request.approver_key, 'payload', v_request.enc_payload);
  end if;
  if v_request.status = 'denied' then
    return jsonb_build_object('status', 'denied');
  end if;
  if v_request.expires_at <= now() then
    return jsonb_build_object('status', 'expired');
  end if;
  return jsonb_build_object('status', 'waiting');
end;
$$;

-- New device: gives up.
create function public.cancel_qr_sign_in(p_id uuid, p_secret text) returns void
language sql volatile security definer set search_path = '' as $$
  delete from private.qr_sign_ins
   where id = p_id and secret_hash = extensions.digest(coalesce(p_secret, ''), 'sha256');
$$;

-- Signed-in device, after reading the QR code: where the request comes from,
-- to show before approving it; null once it is gone, answered or expired.
create function public.qr_sign_in_request(p_id uuid) returns jsonb
language plpgsql stable security definer set search_path = '' as $$
begin
  if (select auth.uid()) is null or not private.password_session() then
    raise exception 'a password session is required' using errcode = '42501';
  end if;
  return (
    select jsonb_build_object('id', r.id, 'platform', r.platform, 'ip', r.ip, 'country', r.country,
                              'created_at', r.created_at, 'expires_at', r.expires_at)
      from private.qr_sign_ins r
     where r.id = p_id and r.status = 'waiting' and r.expires_at > now()
  );
end;
$$;

-- Signed-in device: leaves its key and the sealed email and Secret Key. The
-- first answer is the one the new device gets.
create function public.approve_qr_sign_in(p_id uuid, p_approver_key text, p_enc_payload text) returns boolean
language plpgsql volatile security definer set search_path = '' as $$
begin
  if (select auth.uid()) is null or not private.password_session() then
    raise exception 'a password session is required' using errcode = '42501';
  end if;
  if length(coalesce(p_approver_key, '')) <> 43 or length(coalesce(p_enc_payload, '')) not between 4 and 4096 then
    return false;
  end if;
  update private.qr_sign_ins
     set status = 'approved',
         user_id = (select auth.uid()),
         approver_key = p_approver_key,
         enc_payload = p_enc_payload
   where id = p_id
     and status = 'waiting'
     and expires_at > now();
  return found;
end;
$$;

-- Signed-in device: refuses a request it read.
create function public.deny_qr_sign_in(p_id uuid) returns void
language plpgsql volatile security definer set search_path = '' as $$
begin
  if (select auth.uid()) is null or not private.password_session() then
    raise exception 'a password session is required' using errcode = '42501';
  end if;
  update private.qr_sign_ins
     set status = 'denied', user_id = (select auth.uid())
   where id = p_id and status = 'waiting' and expires_at > now();
end;
$$;

revoke all on function public.start_qr_sign_in(uuid, text, text) from public;
revoke all on function public.qr_sign_in_status(uuid, text) from public;
revoke all on function public.cancel_qr_sign_in(uuid, text) from public;
revoke all on function public.qr_sign_in_request(uuid) from public, anon;
revoke all on function public.approve_qr_sign_in(uuid, text, text) from public, anon;
revoke all on function public.deny_qr_sign_in(uuid) from public, anon;
grant execute on function public.start_qr_sign_in(uuid, text, text) to anon, authenticated;
grant execute on function public.qr_sign_in_status(uuid, text) to anon, authenticated;
grant execute on function public.cancel_qr_sign_in(uuid, text) to anon, authenticated;
grant execute on function public.qr_sign_in_request(uuid) to authenticated;
grant execute on function public.approve_qr_sign_in(uuid, text, text) to authenticated;
grant execute on function public.deny_qr_sign_in(uuid) to authenticated;

-- Requests are kept a day (for the hourly limit), then dropped.
create function private.purge_qr_sign_ins() returns void
language sql volatile security definer set search_path = '' as $$
  delete from private.qr_sign_ins where created_at < now() - interval '1 day';
$$;
revoke all on function private.purge_qr_sign_ins() from public, anon, authenticated;
select cron.schedule('keyless-purge-qr-sign-ins', '27 * * * *', 'select private.purge_qr_sign_ins()');

-- Signing in with a passkey works only where the web vault is published
-- (passkeys are made on its domain), and the web vault is off for now (see
-- apps/site/README.md). A switch turns the server side off as well, so a
-- passkey made before signs in nowhere and no new one can be added. To turn
-- it back on, with the web vault:
--
--   update private.switches set enabled = true where name = 'passkey_sign_in';

create table private.switches (
  name text primary key,
  enabled boolean not null
);
alter table private.switches enable row level security;
revoke all on private.switches from anon, authenticated;
insert into private.switches (name, enabled) values ('passkey_sign_in', false);

create function private.switch_on(p_name text) returns boolean
language sql stable security definer set search_path = '' as $$
  select coalesce((select s.enabled from private.switches s where s.name = p_name), false);
$$;
revoke all on function private.switch_on(text) from public, anon, authenticated;

create or replace function public.add_passkey(p_id uuid, p_credential_id text, p_enc_name text, p_proof text, p_enc_bundle text) returns void
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_uid uuid := (select auth.uid());
begin
  if v_uid is null or not private.password_session() then
    raise exception 'a password session is required' using errcode = '42501';
  end if;
  if not private.switch_on('passkey_sign_in') then
    raise exception 'passkey sign-in is off' using errcode = '55000';
  end if;
  if length(coalesce(p_proof, '')) <> 43 then
    raise exception 'invalid proof' using errcode = '22023';
  end if;
  if (select count(*) from public.passkeys where user_id = v_uid) >= 10 then
    raise exception 'passkey limit reached' using errcode = '54000';
  end if;
  insert into public.passkeys (id, user_id, credential_id, enc_name, verifier, enc_bundle)
  values (p_id, v_uid, p_credential_id, p_enc_name, extensions.digest(p_proof, 'sha256'), p_enc_bundle);
end;
$$;

-- With the right proof for passkey p_credential_id: its account and bundle;
-- otherwise {"error": "passkey_failed" | "passkey_throttled" | "passkey_sign_in_off"}.
-- (Errors are returned, not raised, so failures stay recorded.)
create or replace function public.passkey_sign_in(p_credential_id text, p_proof text) returns jsonb
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_passkey public.passkeys;
  v_email text;
begin
  if not private.switch_on('passkey_sign_in') then
    return jsonb_build_object('error', 'passkey_sign_in_off');
  end if;
  if (select count(*) from private.passkey_failures f
       where f.credential_id = p_credential_id and f.at > now() - interval '1 hour') >= 10 then
    return jsonb_build_object('error', 'passkey_throttled');
  end if;
  select * into v_passkey from public.passkeys where credential_id = p_credential_id;
  if v_passkey.id is null
     or length(coalesce(p_proof, '')) <> 43
     or v_passkey.verifier <> extensions.digest(p_proof, 'sha256') then
    insert into private.passkey_failures (credential_id) values (left(coalesce(p_credential_id, ''), 1400));
    return jsonb_build_object('error', 'passkey_failed');
  end if;
  select u.email into v_email from auth.users u where u.id = v_passkey.user_id and u.deleted_at is null;
  if v_email is null then
    return jsonb_build_object('error', 'passkey_failed');
  end if;
  update public.passkeys set last_used_at = now() where id = v_passkey.id;
  return jsonb_build_object('user_id', v_passkey.user_id, 'email', v_email, 'enc_bundle', v_passkey.enc_bundle);
end;
$$;

-- Account recovery keys, like 1Password's recovery codes (see
-- keyless_core::recovery). A recovery key gets the user back into their
-- account when the master password is forgotten or the Secret Key lost.
-- Whoever has it and knows the account's email gets in, so it is optional,
-- can be removed, and is replaced after each use.
--
-- The server keeps a SHA-256 hash of a proof derived from the key and the
-- user key encrypted with another key derived from it; it never sees the
-- recovery key or the user key. Recovering is two calls, open to anyone:
-- begin_recovery checks the proof and returns what the device needs to
-- decrypt the user key; complete_recovery checks it again, then sets the
-- new sign-in secret and key wrapping the device made (a new master
-- password and Secret Key), replaces the recovery key and ends every
-- session. Failed proofs are limited to 10 an hour per account, and an
-- unknown email fails the same way as a wrong key.

create table private.recovery_keys (
  user_id uuid primary key references auth.users (id) on delete cascade,
  verifier bytea not null,
  enc_user_key text not null check (length(enc_user_key) between 4 and 512),
  created_at timestamptz not null default now()
);

create table private.recovery_failures (
  user_id uuid not null references auth.users (id) on delete cascade,
  at timestamptz not null default now()
);
create index recovery_failures_user_at on private.recovery_failures (user_id, at);

alter table private.recovery_keys enable row level security;
alter table private.recovery_failures enable row level security;

-- The account a recovery is for, when the proof is right; records a failure
-- otherwise. `outcome` is 'ok', 'failed' or 'throttled'.
create function private.check_recovery(p_email text, p_proof text, out user_id uuid, out outcome text)
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_verifier bytea;
begin
  select u.id into user_id
    from auth.users u
   where lower(u.email) = lower(trim(coalesce(p_email, '')))
     and u.deleted_at is null;
  if user_id is null then
    outcome := 'failed';
    return;
  end if;
  if (select count(*) from private.recovery_failures f
       where f.user_id = check_recovery.user_id and f.at > now() - interval '1 hour') >= 10 then
    outcome := 'throttled';
    user_id := null;
    return;
  end if;
  select k.verifier into v_verifier from private.recovery_keys k where k.user_id = check_recovery.user_id;
  if v_verifier is null
     or length(coalesce(p_proof, '')) <> 43
     or v_verifier <> extensions.digest(p_proof, 'sha256') then
    insert into private.recovery_failures (user_id) values (check_recovery.user_id);
    outcome := 'failed';
    user_id := null;
    return;
  end if;
  outcome := 'ok';
end;
$$;

-- Sets (or replaces) the signed-in account's recovery key.
create function public.set_recovery_key(p_proof text, p_enc_user_key text) returns void
language plpgsql volatile security definer set search_path = '' as $$
begin
  if not (select private.password_session()) then
    raise exception 'a password session is required' using errcode = '42501';
  end if;
  if length(coalesce(p_proof, '')) <> 43 then
    raise exception 'invalid proof' using errcode = '22023';
  end if;
  insert into private.recovery_keys (user_id, verifier, enc_user_key)
  values ((select auth.uid()), extensions.digest(p_proof, 'sha256'), p_enc_user_key)
  on conflict (user_id) do update
    set verifier = excluded.verifier, enc_user_key = excluded.enc_user_key, created_at = now();
end;
$$;

-- When the signed-in account's recovery key was made (null without one).
create function public.recovery_key_created() returns timestamptz
language sql stable security definer set search_path = '' as $$
  select k.created_at from private.recovery_keys k
   where k.user_id = (select auth.uid()) and (select private.password_session());
$$;

create function public.remove_recovery_key() returns void
language plpgsql volatile security definer set search_path = '' as $$
begin
  if not (select private.password_session()) then
    raise exception 'a password session is required' using errcode = '42501';
  end if;
  delete from private.recovery_keys where user_id = (select auth.uid());
end;
$$;

-- Step 1: with the right proof, what the device needs to decrypt the user
-- key; otherwise {"error": "recovery_failed" | "recovery_throttled"}.
-- (Errors are returned, not raised, so failures stay recorded.)
create function public.begin_recovery(p_email text, p_proof text) returns jsonb
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_check record;
  v_key private.recovery_keys;
  v_profile public.profiles;
begin
  select * into v_check from private.check_recovery(p_email, p_proof);
  if v_check.outcome <> 'ok' then
    return jsonb_build_object('error', 'recovery_' || v_check.outcome);
  end if;
  select * into v_key from private.recovery_keys where user_id = v_check.user_id;
  select * into v_profile from public.profiles where user_id = v_check.user_id;
  if v_profile is null then
    return jsonb_build_object('error', 'recovery_failed');
  end if;
  return jsonb_build_object(
    'user_id', v_check.user_id,
    'enc_recovery_user_key', v_key.enc_user_key,
    'format', v_profile.format,
    'public_key', v_profile.public_key,
    'enc_private_key', v_profile.enc_private_key
  );
end;
$$;

-- Step 2: with the right proof, the new sign-in secret (stored as Supabase
-- Auth stores passwords), the user key wrapped for the new master password
-- and Secret Key, and the next recovery key. Every session ends.
create function public.complete_recovery(
  p_email text,
  p_proof text,
  p_auth_secret text,
  p_kdf jsonb,
  p_enc_user_key text,
  p_new_proof text,
  p_new_enc_recovery_user_key text
) returns jsonb
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_check record;
begin
  select * into v_check from private.check_recovery(p_email, p_proof);
  if v_check.outcome <> 'ok' then
    return jsonb_build_object('error', 'recovery_' || v_check.outcome);
  end if;
  if length(coalesce(p_auth_secret, '')) <> 43
     or length(coalesce(p_new_proof, '')) <> 43
     or jsonb_typeof(p_kdf) is distinct from 'object'
     or length(coalesce(p_enc_user_key, '')) not between 4 and 512
     or length(coalesce(p_new_enc_recovery_user_key, '')) not between 4 and 512 then
    return jsonb_build_object('error', 'recovery_invalid');
  end if;

  update auth.users
     set encrypted_password = extensions.crypt(p_auth_secret, extensions.gen_salt('bf', 10)),
         updated_at = now()
   where id = v_check.user_id;
  update public.profiles
     set kdf = p_kdf, enc_user_key = p_enc_user_key, pending_kdf = null, pending_enc_user_key = null
   where user_id = v_check.user_id;
  update private.recovery_keys
     set verifier = extensions.digest(p_new_proof, 'sha256'),
         enc_user_key = p_new_enc_recovery_user_key,
         created_at = now()
   where user_id = v_check.user_id;
  delete from private.recovery_failures where user_id = v_check.user_id;
  delete from auth.refresh_tokens where user_id = v_check.user_id::text;
  delete from auth.sessions where user_id = v_check.user_id;
  return jsonb_build_object('ok', true);
end;
$$;

revoke all on function private.check_recovery(text, text) from public, anon, authenticated;
revoke all on function public.set_recovery_key(text, text) from public, anon;
revoke all on function public.recovery_key_created() from public, anon;
revoke all on function public.remove_recovery_key() from public, anon;
revoke all on function public.begin_recovery(text, text) from public;
revoke all on function public.complete_recovery(text, text, text, jsonb, text, text, text) from public;
grant execute on function public.set_recovery_key(text, text) to authenticated;
grant execute on function public.recovery_key_created() to authenticated;
grant execute on function public.remove_recovery_key() to authenticated;
grant execute on function public.begin_recovery(text, text) to anon, authenticated;
grant execute on function public.complete_recovery(text, text, text, jsonb, text, text, text) to anon, authenticated;

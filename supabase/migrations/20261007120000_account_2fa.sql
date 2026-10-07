-- Two-step verification for Keyless accounts, with Supabase Auth's TOTP
-- factors, and recovery codes for losing the authenticator app.
--
-- An account with a verified factor needs it proven in the session (aal2)
-- for everything private.password_session() guards: every table and RPC.
-- A session without it gets the error "keyless_mfa_required" instead of
-- empty results, so the app asks for the code rather than seeing an empty
-- account. Signing in on a device asks for the code once; that session
-- (and its refreshes) keeps it.
--
-- Recovery codes only get past the second step: they still need a session
-- created with the master password and Secret Key. Using one removes the
-- account's factors (and its other codes), so the user sets 2FA up again.
-- Only their SHA-256 hashes (salted with the user id) are stored.

-- The session was created with the secret derived from the master password
-- and Secret Key (what password_session() checked before).
create function private.password_sign_in() returns boolean
language sql stable set search_path = '' as $$
  select coalesce(
    (select bool_or(elem ->> 'method' = 'password')
       from jsonb_array_elements(coalesce((select auth.jwt()) -> 'amr', '[]'::jsonb)) as elem),
    false
  );
$$;
revoke all on function private.password_sign_in() from public, anon;
grant execute on function private.password_sign_in() to authenticated;

create function private.has_second_factor(p_user uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from auth.mfa_factors f
     where f.user_id = p_user and f.status = 'verified'
  );
$$;
revoke all on function private.has_second_factor(uuid) from public, anon;
grant execute on function private.has_second_factor(uuid) to authenticated;

create or replace function private.password_session() returns boolean
language plpgsql stable set search_path = '' as $$
begin
  if not private.password_sign_in() then
    return false;
  end if;
  if coalesce((select auth.jwt()) ->> 'aal', 'aal1') <> 'aal2' and private.has_second_factor((select auth.uid())) then
    raise exception 'keyless_mfa_required' using errcode = 'P0001';
  end if;
  return true;
end;
$$;

-- Tokens issued after the second step (mfa/totp) are accepted like
-- refreshes: only for sessions that proved the password.
create or replace function public.keyless_access_token_hook(event jsonb) returns jsonb
language plpgsql stable set search_path = '' as $$
declare
  method text := coalesce(event ->> 'authentication_method', '');
  password_proven boolean := coalesce(
    (select bool_or(elem ->> 'method' = 'password')
       from jsonb_array_elements(coalesce(event -> 'claims' -> 'amr', '[]'::jsonb)) as elem),
    false
  );
begin
  if method in ('password', 'email/signup') then
    return event;
  end if;
  if method = 'mfa/totp' and password_proven then
    return event;
  end if;
  if method in ('oauth', 'token_refresh') then
    if password_proven or not private.has_keyless_profile((event ->> 'user_id')::uuid) then
      return event;
    end if;
    -- The email goes back only to the app that just completed the Google
    -- sign-in (it holds the PKCE verifier), so it can prefill the sign-in form.
    return jsonb_build_object(
      'error', jsonb_build_object(
        'http_code', 409,
        'message', 'keyless_account_exists:' || coalesce(event -> 'claims' ->> 'email', '')
      )
    );
  end if;
  return jsonb_build_object(
    'error', jsonb_build_object(
      'http_code', 403,
      'message', 'Keyless accounts can only sign in with the master password and Secret Key.'
    )
  );
end;
$$;

create table private.mfa_recovery_codes (
  user_id uuid not null references auth.users (id) on delete cascade,
  -- hex(sha256(user id || ':' || code)), the code in capitals without
  -- separators.
  code_hash text not null check (code_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now(),
  primary key (user_id, code_hash)
);
revoke all on private.mfa_recovery_codes from public, anon, authenticated;

-- Replaces the account's recovery codes (needs the second step proven).
create function public.set_recovery_codes(p_hashes text[]) returns void
language plpgsql security definer set search_path = '' as $$
declare
  uid uuid := (select auth.uid());
begin
  if not private.password_session() or not private.has_second_factor(uid) then
    raise exception 'not allowed' using errcode = '42501';
  end if;
  if coalesce(array_length(p_hashes, 1), 0) not between 1 and 16 then
    raise exception 'bad recovery codes' using errcode = '22023';
  end if;
  delete from private.mfa_recovery_codes where user_id = uid;
  insert into private.mfa_recovery_codes (user_id, code_hash)
  select uid, lower(h) from unnest(p_hashes) as h
  on conflict do nothing;
end;
$$;

-- How many recovery codes are left (0 without two-step verification).
create function public.recovery_codes_left() returns integer
language sql stable security definer set search_path = '' as $$
  select count(*)::integer from private.mfa_recovery_codes c
   where c.user_id = (select auth.uid())
     and (select private.password_session())
     and private.has_second_factor(c.user_id);
$$;

-- Gets past the second step with a recovery code: in a session that proved
-- the password, a matching code turns two-step verification off (the
-- factors and every code go). Returns whether the code matched.
create function public.use_recovery_code(p_code text) returns boolean
language plpgsql security definer set search_path = '' as $$
declare
  uid uuid := (select auth.uid());
  normalized text := upper(regexp_replace(coalesce(p_code, ''), '[^0-9A-Za-z]', '', 'g'));
  hash text;
begin
  if uid is null or not private.password_sign_in() then
    raise exception 'not allowed' using errcode = '42501';
  end if;
  hash := encode(extensions.digest(uid::text || ':' || normalized, 'sha256'), 'hex');
  if not exists (select 1 from private.mfa_recovery_codes where user_id = uid and code_hash = hash) then
    return false;
  end if;
  delete from private.mfa_recovery_codes where user_id = uid;
  delete from auth.mfa_factors where user_id = uid;
  return true;
end;
$$;

-- Turning two-step verification off (the app removes the factor) also
-- clears the codes.
create function public.clear_recovery_codes() returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not private.password_session() then
    raise exception 'not allowed' using errcode = '42501';
  end if;
  delete from private.mfa_recovery_codes where user_id = (select auth.uid());
end;
$$;

revoke all on function public.set_recovery_codes(text[]) from public, anon;
revoke all on function public.recovery_codes_left() from public, anon;
revoke all on function public.use_recovery_code(text) from public, anon;
revoke all on function public.clear_recovery_codes() from public, anon;
grant execute on function public.set_recovery_codes(text[]) to authenticated;
grant execute on function public.recovery_codes_left() to authenticated;
grant execute on function public.use_recovery_code(text) to authenticated;
grant execute on function public.clear_recovery_codes() to authenticated;

-- Sign in with Google.
--
-- Google only identifies the account. Reading or writing data still needs a
-- session created with the secret derived from the master password and Secret
-- Key (private.password_session()), so a Google session reads nothing.
--
-- Google sessions exist only for accounts that are not set up yet (no Keyless
-- profile): the app uses one once, to set the derived secret as the account's
-- password. For an existing account the token request is refused with
-- "keyless_account_exists", and setting up an account ends every session that
-- did not prove the password. Control of a Google account therefore never
-- yields a session that could replace the password of a Keyless account.

create function private.has_keyless_profile(p_user_id uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.profiles where user_id = p_user_id);
$$;
revoke all on function private.has_keyless_profile(uuid) from public, anon, authenticated;
grant usage on schema private to supabase_auth_admin;
grant execute on function private.has_keyless_profile(uuid) to supabase_auth_admin;

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

-- Setting up an account ends the sessions that only proved a Google identity.
create function private.end_identity_only_sessions() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  delete from auth.sessions s
  where s.user_id = new.user_id
    and not exists (
      select 1 from auth.mfa_amr_claims c
      where c.session_id = s.id and c.authentication_method = 'password'
    );
  return new;
end;
$$;
revoke all on function private.end_identity_only_sessions() from public, anon, authenticated;

create trigger profiles_end_identity_sessions
  after insert on public.profiles
  for each row execute function private.end_identity_only_sessions();

-- Lets the app check, with a Google session, whether the account is already
-- set up (a second check besides the hook, before it sets a password).
create function public.keyless_account_exists() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.profiles where user_id = (select auth.uid()));
$$;
revoke all on function public.keyless_account_exists() from public, anon;
grant execute on function public.keyless_account_exists() to authenticated;

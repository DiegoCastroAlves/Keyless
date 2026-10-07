-- Supabase Auth names the second step of TOTP two-step verification "totp"
-- in the access token hook (it is "mfa/phone" for SMS codes), not
-- "mfa/totp": accept it, still only for sessions that proved the password.

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
  if method in ('totp', 'mfa/totp') and password_proven then
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

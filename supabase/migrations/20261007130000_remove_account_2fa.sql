-- Two-step verification is gone again (see account_2fa): the authenticator
-- most people would use is a password manager, so it added a way to be
-- locked out more than protection. Sessions need again only to have proven
-- the master password and Secret Key; recovery codes and any TOTP factors
-- left are removed, and the access token hook no longer accepts the second
-- step. (Supabase Auth's TOTP enrollment should also be turned off in the
-- dashboard: Authentication > Multi-Factor.)

create or replace function private.password_session() returns boolean
language sql stable set search_path = '' as $$
  select coalesce(
    (select bool_or(elem ->> 'method' = 'password')
       from jsonb_array_elements(coalesce((select auth.jwt()) -> 'amr', '[]'::jsonb)) as elem),
    false
  );
$$;

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

drop function public.set_recovery_codes(text[]);
drop function public.recovery_codes_left();
drop function public.use_recovery_code(text);
drop function public.clear_recovery_codes();
drop table private.mfa_recovery_codes;
drop function private.has_second_factor(uuid);
drop function private.password_sign_in();

delete from auth.mfa_factors where factor_type = 'totp';

-- Share links only some people can open, like 1Password's "Only people with
-- specific email addresses". The link still carries the item's key in its
-- fragment; the server also wants proof of one of the emails before it hands
-- out the ciphertext.
--
-- The owner's app stores the SHA-256 of each allowed email (lowercase).
-- open_share() no longer gives out such a link's ciphertext: it says the link
-- is restricted, the share page asks for the visitor's email, Supabase Auth
-- sends a one-time code, and with the session the code gives,
-- open_restricted_share() checks the email against the list.
--
-- Those sessions belong to throwaway Auth users (marked in their metadata).
-- The access token hook allows email-code sessions only for users without a
-- Keyless account; Keyless accounts still sign in only with the master
-- password and Secret Key. Email-code sessions have no 'password' in amr, so
-- they read nothing else. The daily purge removes the throwaway users.
--
-- Supabase Auth must send the codes: the "Confirm signup" and "Magic Link"
-- email templates need {{ .Token }}, and the project needs its own SMTP
-- server (the built-in one only writes to the project's team).

alter table public.shares
  add column recipients bytea[]
    check (recipients is null or (cardinality(recipients) between 1 and 20 and array_position(recipients, null) is null));

grant select (recipients) on public.shares to authenticated;
grant insert (recipients) on public.shares to authenticated;

-- Anyone with the link: its ciphertext, counting the view. A restricted link
-- only says so (without counting a view). Nothing for a link that does not
-- exist, expired, was revoked or was viewed enough times.
create or replace function public.open_share(p_id uuid) returns jsonb
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_result jsonb;
begin
  if exists (
    select 1 from public.shares s
     where s.id = p_id
       and s.recipients is not null
       and s.revoked_at is null
       and s.expires_at > now()
       and (s.max_views is null or s.views < s.max_views)
  ) then
    return jsonb_build_object('restricted', true);
  end if;
  update public.shares s
     set views = s.views + 1
   where s.id = p_id
     and s.recipients is null
     and s.revoked_at is null
     and s.expires_at > now()
     and (s.max_views is null or s.views < s.max_views)
  returning jsonb_build_object(
    'payload', s.enc_payload,
    'expiresAt', s.expires_at,
    'viewsLeft', case when s.max_views is null then null else s.max_views - s.views end
  ) into v_result;
  return v_result;
end;
$$;

-- A restricted link, for a session that proved one of its emails:
-- its ciphertext (counting the view), {"error": "share_not_allowed"} for
-- another email, nothing when the link cannot be opened.
create function public.open_restricted_share(p_id uuid) returns jsonb
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_email text;
  v_result jsonb;
begin
  select lower(trim(u.email)) into v_email
    from auth.users u
   where u.id = (select auth.uid())
     and u.email_confirmed_at is not null;
  if v_email is null or v_email = '' then
    return null;
  end if;
  update public.shares s
     set views = s.views + 1
   where s.id = p_id
     and s.recipients is not null
     and extensions.digest(v_email, 'sha256') = any (s.recipients)
     and s.revoked_at is null
     and s.expires_at > now()
     and (s.max_views is null or s.views < s.max_views)
  returning jsonb_build_object(
    'payload', s.enc_payload,
    'expiresAt', s.expires_at,
    'viewsLeft', case when s.max_views is null then null else s.max_views - s.views end
  ) into v_result;
  if v_result is null and exists (
    select 1 from public.shares s
     where s.id = p_id and s.recipients is not null and s.revoked_at is null and s.expires_at > now()
       and (s.max_views is null or s.views < s.max_views)
  ) then
    return jsonb_build_object('error', 'share_not_allowed');
  end if;
  return v_result;
end;
$$;
revoke all on function public.open_restricted_share(uuid) from public, anon;
grant execute on function public.open_restricted_share(uuid) to authenticated;

-- Email-code sessions ('otp', 'magiclink') only for users without a Keyless
-- account: the people links are restricted to.
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
  if method in ('otp', 'magiclink') and not private.has_keyless_profile((event ->> 'user_id')::uuid) then
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

-- The daily purge also removes the throwaway users of restricted links
-- (never one that became a Keyless account).
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
  delete from auth.users u
   where u.raw_user_meta_data ->> 'keyless_share_recipient' = 'true'
     and u.created_at < now() - interval '30 days'
     and (u.last_sign_in_at is null or u.last_sign_in_at < now() - interval '30 days')
     and not exists (select 1 from public.profiles p where p.user_id = u.id);
  delete from auth.users
   where id in (select user_id from public.profiles where delete_after < now());
end;
$$;
revoke all on function private.purge_expired() from public, anon, authenticated;

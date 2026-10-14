-- Signing in with a passkey (see keyless_core::passkey_login): the WebAuthn
-- PRF extension gives the device a secret only the passkey can produce, from
-- which come a proof and a key. The server keeps the SHA-256 of the proof
-- and a bundle encrypted with the key (what signing in needs: the auth
-- secret, the user key and the Secret Key). It never sees the PRF output,
-- the key or what the bundle holds.
--
-- passkey_sign_in() is open to anyone: with the right proof for a passkey it
-- returns that passkey's bundle and account; failures are limited to 10 an
-- hour per passkey, and an unknown passkey fails the same way.
--
-- A bundle holds the auth secret of its time, so a new one (master password
-- or Secret Key changed, account recovered) drops the account's passkeys.

create table public.passkeys (
  id uuid primary key,
  user_id uuid not null references auth.users (id) on delete cascade,
  credential_id text not null unique check (length(credential_id) between 16 and 1400),
  enc_name text not null check (length(enc_name) between 4 and 1024),
  verifier bytea not null,
  enc_bundle text not null check (length(enc_bundle) between 4 and 4096),
  created_at timestamptz not null default now(),
  last_used_at timestamptz
);
create index passkeys_user_idx on public.passkeys (user_id);

create table private.passkey_failures (
  credential_id text not null,
  at timestamptz not null default now()
);
create index passkey_failures_idx on private.passkey_failures (credential_id, at);

alter table public.passkeys enable row level security;
alter table private.passkey_failures enable row level security;

create policy "own passkeys: read" on public.passkeys
  for select to authenticated
  using (user_id = (select auth.uid()) and (select private.password_session()));

revoke all on public.passkeys from anon, authenticated;
grant select (id, credential_id, enc_name, created_at, last_used_at) on public.passkeys to authenticated;

-- Adds a passkey to the signed-in account (10 at most).
create function public.add_passkey(p_id uuid, p_credential_id text, p_enc_name text, p_proof text, p_enc_bundle text) returns void
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_uid uuid := (select auth.uid());
begin
  if v_uid is null or not private.password_session() then
    raise exception 'a password session is required' using errcode = '42501';
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

create function public.remove_passkey(p_id uuid) returns void
language plpgsql volatile security definer set search_path = '' as $$
begin
  if (select auth.uid()) is null or not private.password_session() then
    raise exception 'a password session is required' using errcode = '42501';
  end if;
  delete from public.passkeys where id = p_id and user_id = (select auth.uid());
end;
$$;

-- With the right proof for passkey p_credential_id: its account and bundle;
-- otherwise {"error": "passkey_failed" | "passkey_throttled"}. (Errors are
-- returned, not raised, so failures stay recorded.)
create function public.passkey_sign_in(p_credential_id text, p_proof text) returns jsonb
language plpgsql volatile security definer set search_path = '' as $$
declare
  v_passkey public.passkeys;
  v_email text;
begin
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

revoke all on function public.add_passkey(uuid, text, text, text, text) from public, anon;
revoke all on function public.remove_passkey(uuid) from public, anon;
revoke all on function public.passkey_sign_in(text, text) from public;
grant execute on function public.add_passkey(uuid, text, text, text, text) to authenticated;
grant execute on function public.remove_passkey(uuid) to authenticated;
grant execute on function public.passkey_sign_in(text, text) to anon, authenticated;

-- A new sign-in secret makes the bundles useless: drop them.
create function private.drop_passkeys() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  delete from public.passkeys where user_id = new.id;
  return new;
end;
$$;
revoke all on function private.drop_passkeys() from public, anon, authenticated;

create trigger keyless_drop_passkeys
  after update of encrypted_password on auth.users
  for each row
  when (old.encrypted_password is distinct from new.encrypted_password)
  execute function private.drop_passkeys();

-- Failed attempts are kept a day.
create function private.purge_passkey_failures() returns void
language sql volatile security definer set search_path = '' as $$
  delete from private.passkey_failures where at < now() - interval '1 day';
$$;
revoke all on function private.purge_passkey_failures() from public, anon, authenticated;
select cron.schedule('keyless-purge-passkey-failures', '41 4 * * *', 'select private.purge_passkey_failures()');

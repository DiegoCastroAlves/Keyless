-- Settings that follow an account to all its devices (for now, the defaults
-- of suggested passwords). Each device seals them with the account's user
-- key, like everything else: the server keeps a blob it cannot read, and
-- only its owner can read or change it (the profile's own policies).

alter table public.profiles
  add column enc_settings text check (length(enc_settings) between 4 and 16384);

grant update (enc_settings) on public.profiles to authenticated;

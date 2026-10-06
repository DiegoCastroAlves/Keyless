//! Build-time configuration. Both values are public by design: the
//! publishable key only identifies the project, and every table is protected
//! by Row Level Security. Override them at build time to point Keyless at
//! another (e.g. self-hosted) Supabase project.

pub const SUPABASE_URL: &str = match option_env!("KEYLESS_SUPABASE_URL") {
    Some(url) => url,
    None => "https://ednfhgbjtgkrmtnudcjr.supabase.co",
};

pub const SUPABASE_PUBLISHABLE_KEY: &str = match option_env!("KEYLESS_SUPABASE_KEY") {
    Some(key) => key,
    None => "sb_publishable_3SSYrJqgt-zB30WaRHnuSw_YN7WaHqD",
};

/// Service name used for entries in the OS credential store.
pub const KEYRING_SERVICE: &str = "Keyless";

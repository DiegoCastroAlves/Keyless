//! A made-up account with a vault and a few logins, for testing the apps
//! against a local fake server (apps/android/scripts/mock_server.py). Prints
//! JSON: the credentials to type, and the rows the server would keep.
//!
//! `cargo run -p keyless-client --example fixture > fixture.json`

use keyless_core::{
    account::create_account,
    item::{Category, Field, FieldKind, FieldPurpose, ItemDetails, ItemOverview, ItemUrl, stamp_version},
    keys::{KdfParams, SecretKey, derive_account_keys},
    vault::{VaultKey, VaultMeta},
};
use serde_json::json;

const USER: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const VAULT: &str = "bbbbbbbb-0000-4000-8000-000000000001";

fn login(title: &str, url: &str, username: &str, password: &str) -> (ItemOverview, ItemDetails) {
    let mut overview = ItemOverview {
        title: title.into(),
        subtitle: username.into(),
        category: Category::Login,
        urls: vec![ItemUrl { href: url.into(), ..Default::default() }],
        created_at: 1_790_000_000,
        updated_at: 1_790_000_000,
        ..Default::default()
    };
    let mut details = ItemDetails::default();
    let field = |id: &str, label: &str, kind, value: &str, purpose| Field { id: id.into(), label: label.into(), kind, value: value.into(), purpose, extra: Default::default() };
    details.fields.push(field("u", "username", FieldKind::Text, username, Some(FieldPurpose::Username)));
    details.fields.push(field("p", "password", FieldKind::Concealed, password, Some(FieldPurpose::Password)));
    details.fields.push(field("t", "one-time password", FieldKind::Totp, "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP", None));
    details.notes = "Made up for tests.".into();
    stamp_version(&mut overview, &mut details, 1);
    (overview, details)
}

fn main() {
    let secret_key = SecretKey::generate().unwrap();
    let master_password = "correct horse battery staple 42";
    let kdf = KdfParams::recommended();
    let keys = derive_account_keys(master_password, &secret_key, &kdf).unwrap();
    let (bundle, account) = create_account(&keys.kek, kdf, USER).unwrap();
    let vault_key = VaultKey::generate().unwrap();
    let meta = VaultMeta { name: "Personal".into(), icon: "user".into(), ..Default::default() };
    let logins = [
        ("cccccccc-0000-4000-8000-000000000001", login("Form test", "android://io.github.diegocastroalves.keyless.formtest", "tester", "s3cret-form-pass")),
        ("cccccccc-0000-4000-8000-000000000002", login("GitHub", "https://github.com", "octo", "github-pass-123")),
        ("cccccccc-0000-4000-8000-000000000003", login("Bank", "https://bank.example", "client", "bank-pass-456")),
    ];
    let items: Vec<_> = logins
        .iter()
        .enumerate()
        .map(|(i, (id, (overview, details)))| {
            json!({
                "id": id,
                "vault_id": VAULT,
                "enc_overview": vault_key.seal_overview(VAULT, id, overview).unwrap(),
                "enc_details": vault_key.seal_details(VAULT, id, details).unwrap(),
                "revision": 1,
                "seq": i + 1,
                "deleted_at": null,
                "enc_tombstone": null,
            })
        })
        .collect();
    let fixture = json!({
        "email": "tester@example.test",
        "secretKey": secret_key.to_display().as_str(),
        "masterPassword": master_password,
        "authSecret": keys.auth_secret.as_str(),
        "userId": USER,
        "profile": bundle,
        "memberships": [{
            "vault_id": VAULT,
            "role": "owner",
            "enc_vault_key": vault_key.wrap(account.user_key(), VAULT).unwrap(),
            "vaults": { "owner_id": USER, "enc_meta": vault_key.seal_meta(VAULT, &meta).unwrap(), "seq": 1, "deleted_at": null, "enc_tombstone": null },
        }],
        "items": items,
    });
    println!("{fixture}");
}

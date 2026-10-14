use keyless_core::{
    account::create_account,
    item::{Field, FieldKind, FieldPurpose, ItemUrl},
    keys::derive_account_keys,
    vault::Tombstone,
};

use super::*;

const PASSWORD: &str = "correct horse battery staple";
const USER: &str = "11111111-1111-4111-8111-111111111111";
const VAULT: &str = "22222222-2222-4222-8222-222222222222";

struct Server {
    secret_key: String,
    profile: Value,
    vault_key: VaultKey,
    membership: Value,
}

fn server() -> Server {
    let secret_key = SecretKey::generate().unwrap();
    let kdf = KdfParams::recommended();
    let keys = derive_account_keys(PASSWORD, &secret_key, &kdf).unwrap();
    let (bundle, account) = create_account(&keys.kek, kdf, USER).unwrap();
    let vault_key = VaultKey::generate().unwrap();
    let meta = VaultMeta { name: "Personal".into(), icon: "user".into(), ..Default::default() };
    let membership = json!([{
        "vault_id": VAULT,
        "role": "owner",
        "enc_vault_key": vault_key.wrap(account.user_key(), VAULT).unwrap(),
        "vaults": { "owner_id": USER, "enc_meta": vault_key.seal_meta(VAULT, &meta).unwrap(), "seq": 1, "deleted_at": null, "enc_tombstone": null },
    }]);
    let profile = serde_json::to_value(&bundle).unwrap();
    Server { secret_key: secret_key.to_display().to_string(), profile, vault_key, membership }
}

fn login(title: &str, url: &str, password: &str, version: u64) -> (ItemOverview, ItemDetails) {
    let mut overview = ItemOverview { title: title.into(), category: Category::Login, urls: vec![ItemUrl { href: url.into(), ..Default::default() }], ..Default::default() };
    let mut details = ItemDetails::default();
    details.fields.push(Field { id: "u".into(), label: "username".into(), kind: FieldKind::Text, value: "me".into(), purpose: Some(FieldPurpose::Username), extra: Default::default() });
    details.fields.push(Field { id: "p".into(), label: "password".into(), kind: FieldKind::Concealed, value: password.into(), purpose: Some(FieldPurpose::Password), extra: Default::default() });
    details.fields.push(Field { id: "t".into(), label: "one-time password".into(), kind: FieldKind::Totp, value: "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".into(), purpose: None, extra: Default::default() });
    stamp_version(&mut overview, &mut details, version);
    (overview, details)
}

fn row(server: &Server, id: &str, seq: i64, revision: i64, item: &(ItemOverview, ItemDetails)) -> Value {
    json!({
        "id": id,
        "vault_id": VAULT,
        "enc_overview": server.vault_key.seal_overview(VAULT, id, &item.0).unwrap(),
        "enc_details": server.vault_key.seal_details(VAULT, id, &item.1).unwrap(),
        "revision": revision,
        "seq": seq,
        "deleted_at": null,
        "enc_tombstone": null,
    })
}

fn ok(answer: String) -> Value {
    let value: Value = serde_json::from_str(&answer).unwrap();
    assert!(value.get("error").is_none(), "{value}");
    value["ok"].clone()
}

fn error(answer: String) -> String {
    let value: Value = serde_json::from_str(&answer).unwrap();
    value["error"]["key"].as_str().unwrap_or_else(|| panic!("expected an error, got {value}")).to_string()
}

fn signed_in(server: &Server) -> Client {
    let mut client = Client::new();
    let derived = ok(client.call("derive", &json!({ "email": "Me@Example.com", "masterPassword": PASSWORD, "secretKey": server.secret_key }).to_string()));
    assert_eq!(derived["authSecret"].as_str().unwrap().len(), 43);
    let status = ok(client.call("signedIn", &json!({ "userId": USER, "profile": server.profile }).to_string()));
    assert_eq!(status["email"], "me@example.com");
    assert_eq!(status["unlocked"], true);
    ok(client.call("applyMemberships", &server.membership.to_string()));
    client
}

#[test]
fn signs_in_syncs_and_reads() {
    let server = server();
    let mut client = signed_in(&server);
    assert_eq!(ok(client.call("vaults", ""))[0]["name"], "Personal");

    const A: &str = "33333333-3333-4333-8333-333333333333";
    const B: &str = "44444444-4444-4444-8444-444444444444";
    let items = json!([row(&server, A, 5, 1, &login("GitHub", "https://github.com", "pw1", 1)), row(&server, B, 6, 1, &login("Bank", "https://bank.example", "pw2", 1))]);
    let applied = ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": items }).to_string()));
    assert_eq!(applied["cursor"], 6);
    assert_eq!(applied["changed"], 2);
    assert_eq!(ok(client.call("cursor", &json!({ "vaultId": VAULT }).to_string())), 6);

    let list = ok(client.call("items", ""));
    assert_eq!(list.as_array().unwrap().len(), 2);
    let item = ok(client.call("item", &json!({ "id": A }).to_string()));
    assert_eq!(item["details"]["fields"][1]["value"], "pw1");

    let code = ok(client.call("totp", &json!({ "uri": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP", "now": 59 }).to_string()));
    assert_eq!(code["code"].as_str().unwrap().len(), 6);
    assert_eq!(code["remaining"], 1);

    let found = ok(client.call("match", &json!({ "domain": "gist.github.com" }).to_string()));
    assert_eq!(found.as_array().unwrap().len(), 1);
    assert_eq!(found[0]["overview"]["title"], "GitHub");
}

#[test]
fn refuses_what_the_server_should_not_send() {
    let server = server();
    let mut client = signed_in(&server);
    const A: &str = "33333333-3333-4333-8333-333333333333";
    let v2 = login("GitHub", "https://github.com", "new", 2);
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [row(&server, A, 5, 2, &v2)] }).to_string()));

    // An older version (rollback).
    let v1 = login("GitHub", "https://github.com", "old", 1);
    let applied = ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [row(&server, A, 7, 3, &v1)] }).to_string()));
    assert_eq!(applied["rejected"], 1);
    // Overview and details of different writes.
    let other = login("GitHub", "https://github.com", "mix", 3);
    let mut mixed = row(&server, A, 8, 4, &other);
    mixed["enc_details"] = row(&server, A, 8, 4, &login("x", "y", "z", 3))["enc_details"].clone();
    assert_eq!(ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [mixed] }).to_string()))["rejected"], 1);
    // Encrypted for another item id.
    let mut moved = row(&server, "55555555-5555-4555-8555-555555555555", 9, 1, &other);
    moved["id"] = json!(A);
    assert_eq!(ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [moved] }).to_string()))["rejected"], 1);
    // A deletion without a valid tombstone.
    let deletion = json!({ "id": A, "vault_id": VAULT, "enc_overview": null, "enc_details": null, "revision": 5, "seq": 10, "deleted_at": "2026-10-13T00:00:00Z", "enc_tombstone": "k1.forged" });
    assert_eq!(ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [deletion] }).to_string()))["rejected"], 1);
    assert_eq!(ok(client.call("item", &json!({ "id": A }).to_string()))["details"]["fields"][1]["value"], "new");
    // A genuine, newer deletion.
    let tombstone = server.vault_key.seal_tombstone(VAULT, A, &Tombstone { version: 3, deleted_at: 1 }).unwrap();
    let deletion = json!({ "id": A, "vault_id": VAULT, "enc_overview": null, "enc_details": null, "revision": 6, "seq": 11, "deleted_at": "2026-10-13T00:00:00Z", "enc_tombstone": tombstone });
    assert_eq!(ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [deletion] }).to_string()))["changed"], 1);
    assert_eq!(error(client.call("item", &json!({ "id": A }).to_string())), "not_found");
    assert_eq!(ok(client.call("cursor", &json!({ "vaultId": VAULT }).to_string())), 11);
}

#[test]
fn writes_and_reads_its_own_writes() {
    let server = server();
    let mut client = signed_in(&server);
    let (overview, details) = login("New", "https://new.example", "pw", 0);
    let sealed = ok(client.call("sealItem", &json!({ "vaultId": VAULT, "overview": overview, "details": details, "now": 1_700_000_000 }).to_string()));
    assert!(sealed["baseRevision"].is_null());
    let id = sealed["id"].as_str().unwrap().to_string();
    // What the server answers after the insert.
    let stored = json!({ "id": id, "vault_id": VAULT, "enc_overview": sealed["encOverview"], "enc_details": sealed["encDetails"], "revision": 1, "seq": 20, "deleted_at": null, "enc_tombstone": null });
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [stored] }).to_string()));
    let item = ok(client.call("item", &json!({ "id": id }).to_string()));
    assert_eq!(item["overview"]["subtitle"], "me");
    assert_eq!(item["overview"]["version"], 1);
    assert_eq!(item["overview"]["created_at"], 1_700_000_000);

    // An edit, from the decrypted item.
    let mut details = item["details"].clone();
    details["fields"][1]["value"] = json!("changed");
    let sealed = ok(client.call("sealItem", &json!({ "vaultId": VAULT, "id": id, "overview": item["overview"], "details": details, "now": 1_700_000_100 }).to_string()));
    assert_eq!(sealed["baseRevision"], 1);
    let stored = json!({ "id": id, "vault_id": VAULT, "enc_overview": sealed["encOverview"], "enc_details": sealed["encDetails"], "revision": 2, "seq": 21, "deleted_at": null, "enc_tombstone": null });
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [stored] }).to_string()));
    let item = ok(client.call("item", &json!({ "id": id }).to_string()));
    assert_eq!(item["details"]["fields"][1]["value"], "changed");
    assert_eq!(item["overview"]["version"], 2);
}

#[test]
fn keeps_only_ciphertext_and_unlocks_again() {
    let server = server();
    let mut client = signed_in(&server);
    const A: &str = "33333333-3333-4333-8333-333333333333";
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [row(&server, A, 5, 1, &login("GitHub", "https://github.com", "hunter2", 1))] }).to_string()));
    let snapshot = ok(client.call("snapshot", "")).to_string();
    assert!(!snapshot.contains("hunter2") && !snapshot.contains("GitHub") && !snapshot.contains("Personal"));

    let user_key = ok(client.call("exportUserKey", "")).as_str().unwrap().to_string();
    let mut again = Client::new();
    assert_eq!(ok(again.call("load", &snapshot))["unlocked"], false);
    assert_eq!(error(again.call("items", "")), "locked");
    assert_eq!(error(again.call("unlock", &json!({ "email": "me@example.com", "masterPassword": "wrong password!", "secretKey": server.secret_key }).to_string())), "wrong_password");
    ok(again.call("unlock", &json!({ "email": "me@example.com", "masterPassword": PASSWORD, "secretKey": server.secret_key }).to_string()));
    assert_eq!(ok(again.call("item", &json!({ "id": A }).to_string()))["details"]["fields"][1]["value"], "hunter2");
    ok(again.call("lock", ""));
    ok(again.call("unlockWithUserKey", &json!({ "userKey": user_key }).to_string()));
    assert_eq!(ok(again.call("items", "")).as_array().unwrap().len(), 1);
}

#[test]
fn reads_setup_codes_and_device_answers() {
    let server = server();
    let mut client = Client::new();
    let key = SecretKey::parse(&server.secret_key).unwrap();
    let link = setup_code::setup_link("me@example.com", &key);
    let parsed = ok(client.call("parseSetupLink", &json!({ "text": link.as_str() }).to_string()));
    assert_eq!(parsed["secretKey"], server.secret_key);

    let started = ok(client.call("setupStart", ""));
    let approval = keyless_core::device_setup::SetupApproval::new(started["publicKey"].as_str().unwrap(), started["commitment"].as_str().unwrap()).unwrap();
    let shown = ok(client.call("setupCode", &json!({ "approverKey": approval.public_key(), "approverNonce": approval.nonce() }).to_string()));
    assert_eq!(approval.code(shown["nonce"].as_str().unwrap()).unwrap(), shown["code"].as_str().unwrap());
    let payload = SetupPayload { email: "me@example.com".into(), secret_key: Zeroizing::new(server.secret_key.clone()) };
    let sealed = approval.seal("req", shown["nonce"].as_str().unwrap(), &payload).unwrap();
    let opened = ok(client.call("setupOpen", &json!({ "requestId": "req", "approverKey": approval.public_key(), "approverNonce": approval.nonce(), "payload": sealed }).to_string()));
    assert_eq!(opened["secretKey"], server.secret_key);
}

#[test]
fn signs_in_with_a_passkey() {
    let server = server();
    let mut client = signed_in(&server);
    let prf = URL_SAFE_NO_PAD.encode([9u8; 32]);
    let registered = ok(client.call("passkeyRegister", &json!({ "prfOutput": prf, "credentialId": "cred-1", "name": "YubiKey" }).to_string()));
    let rows = json!([{ "id": "p1", "credential_id": "cred-1", "enc_name": registered["encName"] }]);
    assert_eq!(ok(client.call("passkeyNames", &rows.to_string()))[0]["name"], "YubiKey");

    // Another device: only the passkey.
    let mut other = Client::new();
    let proof = ok(other.call("passkeyProof", &json!({ "prfOutput": prf, "credentialId": "cred-1" }).to_string()));
    assert_eq!(proof["proof"], registered["proof"]);
    assert_eq!(
        error(other.call("passkeyOpen", &json!({ "prfOutput": URL_SAFE_NO_PAD.encode([1u8; 32]), "credentialId": "cred-1", "userId": USER, "encBundle": registered["encBundle"] }).to_string())),
        "passkey_failed"
    );
    let opened = ok(other.call("passkeyOpen", &json!({ "prfOutput": prf, "credentialId": "cred-1", "userId": USER, "encBundle": registered["encBundle"] }).to_string()));
    assert_eq!(opened["secretKey"], server.secret_key);
    assert_eq!(opened["email"], "me@example.com");
    ok(other.call("signedIn", &json!({ "userId": USER, "profile": server.profile }).to_string()));
    ok(other.call("applyMemberships", &server.membership.to_string()));
    assert_eq!(ok(other.call("vaults", ""))[0]["name"], "Personal");
    // With the Secret Key it got, the master password unlocks it later.
    ok(other.call("lock", ""));
    ok(other.call("unlock", &json!({ "email": "me@example.com", "masterPassword": PASSWORD, "secretKey": opened["secretKey"] }).to_string()));

    // Unlocked with biometrics, there is no auth secret to put in a passkey.
    let user_key = ok(client.call("exportUserKey", "")).as_str().unwrap().to_string();
    ok(client.call("lock", ""));
    ok(client.call("unlockWithUserKey", &json!({ "userKey": user_key }).to_string()));
    assert_eq!(error(client.call("passkeyRegister", &json!({ "prfOutput": prf, "credentialId": "cred-2" }).to_string())), "passkey_needs_password");
}

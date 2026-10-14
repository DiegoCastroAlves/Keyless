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

#[test]
fn saves_logins_from_autofill() {
    let server = server();
    let mut client = signed_in(&server);
    let sealed = ok(client.call("sealLogin", &json!({ "url": "https://shop.example", "username": "me", "password": "first", "now": 100 }).to_string()));
    let id = sealed["id"].as_str().unwrap().to_string();
    assert_eq!(sealed["vaultId"], VAULT);
    let stored = json!({ "id": id, "vault_id": VAULT, "enc_overview": sealed["encOverview"], "enc_details": sealed["encDetails"], "revision": 1, "seq": 30, "deleted_at": null, "enc_tombstone": null });
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [stored] }).to_string()));
    let item = ok(client.call("item", &json!({ "id": id }).to_string()));
    assert_eq!(item["overview"]["title"], "shop.example");
    assert_eq!(item["overview"]["subtitle"], "me");

    // The same site and username: found, and a new password replaces the old one.
    let found = ok(client.call("findLogin", &json!({ "domain": "www.shop.example", "username": "ME" }).to_string()));
    assert_eq!(found, json!(id));
    assert!(ok(client.call("findLogin", &json!({ "domain": "shop.example", "username": "other" }).to_string())).is_null());
    assert!(ok(client.call("sealLogin", &json!({ "id": id, "password": "first", "now": 200 }).to_string())).is_null());
    let sealed = ok(client.call("sealLogin", &json!({ "id": id, "password": "second", "now": 200 }).to_string()));
    assert_eq!(sealed["baseRevision"], 1);
    let stored = json!({ "id": id, "vault_id": VAULT, "enc_overview": sealed["encOverview"], "enc_details": sealed["encDetails"], "revision": 2, "seq": 31, "deleted_at": null, "enc_tombstone": null });
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [stored] }).to_string()));
    let item = ok(client.call("item", &json!({ "id": id }).to_string()));
    assert_eq!(item["details"]["fields"][1]["value"], "second");
    assert_eq!(item["details"]["password_history"][0]["value"], "first");
}

#[test]
fn makes_and_uses_passkeys_for_android() {
    use keyless_core::passkey::client_data_json;
    use sha2::{Digest, Sha256};

    let server = server();
    let mut client = signed_in(&server);
    let made = ok(client.call(
        "passkeyNew",
        &json!({ "rpId": "Example.com", "rpName": "Example", "userHandle": URL_SAFE_NO_PAD.encode(b"user-1"), "userName": "me", "userVerified": true, "now": 10 }).to_string(),
    ));
    let item = &made["item"];
    assert!(item["baseRevision"].is_null());
    let stored = json!({ "id": item["id"], "vault_id": VAULT, "enc_overview": item["encOverview"], "enc_details": item["encDetails"], "revision": 1, "seq": 40, "deleted_at": null, "enc_tombstone": null });
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [stored] }).to_string()));

    let found = ok(client.call("passkeysFor", &json!({ "rpId": "example.com" }).to_string()));
    assert_eq!(found.as_array().unwrap().len(), 1);
    assert_eq!(found[0]["credentialId"], made["credentialId"]);
    assert_eq!(ok(client.call("passkeysFor", &json!({ "rpId": "example.com", "allowCredentials": ["other"] }).to_string())).as_array().unwrap().len(), 0);
    // A second one for the same account is refused when the site excludes the first.
    assert_eq!(
        error(client.call("passkeyNew", &json!({ "rpId": "example.com", "userHandle": "dXNlcg", "userName": "me", "excludeCredentials": [made["credentialId"]], "now": 11 }).to_string())),
        "passkey_excluded"
    );

    // Signing in, with the hash a browser made.
    let client_data = client_data_json("webauthn.get", b"challenge", "https://example.com", None);
    let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(client_data.as_bytes()));
    let signed = ok(client.call("passkeyGet", &json!({ "itemId": item["id"], "credentialId": made["credentialId"], "clientDataHash": hash, "userVerified": true }).to_string()));
    let same = ok(client.call("passkeyGet", &json!({ "itemId": item["id"], "credentialId": made["credentialId"], "clientDataJson": client_data, "userVerified": true }).to_string()));
    assert_eq!(signed["authenticatorData"], same["authenticatorData"]);
    assert_eq!(URL_SAFE_NO_PAD.decode(signed["userHandle"].as_str().unwrap()).unwrap(), b"user-1");
    // The signature checks out with the public key the site got.
    use p256::{ecdsa::{DerSignature, VerifyingKey, signature::Verifier}, pkcs8::DecodePublicKey};
    let key = VerifyingKey::from_public_key_der(&URL_SAFE_NO_PAD.decode(made["publicKey"].as_str().unwrap()).unwrap()).unwrap();
    let mut message = URL_SAFE_NO_PAD.decode(signed["authenticatorData"].as_str().unwrap()).unwrap();
    message.extend_from_slice(&Sha256::digest(client_data.as_bytes()));
    let signature = DerSignature::try_from(URL_SAFE_NO_PAD.decode(signed["signature"].as_str().unwrap()).unwrap().as_slice()).unwrap();
    key.verify(&message, &signature).unwrap();
}

#[test]
fn generates_passwords() {
    let mut client = Client::new();
    let random = ok(client.call("generate", &json!({ "kind": "random", "length": 20 }).to_string()));
    assert_eq!(random["password"].as_str().unwrap().chars().count(), 20);
    let pin = ok(client.call("generate", &json!({ "kind": "pin", "length": 6 }).to_string()));
    assert!(pin["password"].as_str().unwrap().chars().all(|c| c.is_ascii_digit()));
    let words = ok(client.call("generate", &json!({ "kind": "memorable", "words": 4, "separator": "-" }).to_string()));
    assert_eq!(words["password"].as_str().unwrap().split('-').count(), 4);
    assert_eq!(error(client.call("generate", &json!({ "kind": "random", "length": 2 }).to_string())), "invalid_request");
}

/// The server's row after a write of `sealed` (content or tombstone).
fn stored(sealed: &Value, revision: i64, seq: i64) -> Value {
    let deleted = sealed.get("encTombstone").is_some_and(|t| !t.is_null());
    json!({
        "id": sealed["id"],
        "vault_id": VAULT,
        "enc_overview": if deleted { Value::Null } else { sealed["encOverview"].clone() },
        "enc_details": if deleted { Value::Null } else { sealed["encDetails"].clone() },
        "revision": revision,
        "seq": seq,
        "deleted_at": if deleted { json!("2026-10-14T00:00:00Z") } else { Value::Null },
        "enc_tombstone": sealed.get("encTombstone").cloned().unwrap_or(Value::Null),
    })
}

#[test]
fn deletes_for_good() {
    let server = server();
    let mut client = signed_in(&server);
    let item = login("Old", "https://old.example", "pw", 3);
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [row(&server, "i1", 5, 4, &item)] }).to_string()));
    let sealed = ok(client.call("sealTombstone", &json!({ "id": "i1", "now": 1_700_000_000 }).to_string()));
    assert_eq!(sealed["baseRevision"], 4);
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [stored(&sealed, 5, 6)] }).to_string()));
    assert_eq!(error(client.call("item", &json!({ "id": "i1" }).to_string())), "not_found");
    assert_eq!(ok(client.call("items", "")).as_array().unwrap().len(), 0);
}

#[test]
fn settles_conflicts_like_the_desktop() {
    let server = server();
    let mut client = signed_in(&server);
    let base = login("Bank", "https://bank.example", "one", 2);
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [row(&server, "i1", 5, 2, &base)] }).to_string()));
    let item = ok(client.call("item", &json!({ "id": "i1" }).to_string()));
    let mut details = item["details"].clone();
    details["fields"][1]["value"] = json!("ours");
    let ours = ok(client.call("sealItem", &json!({ "vaultId": VAULT, "id": "i1", "overview": item["overview"], "details": details, "now": 1_000 }).to_string()));
    let plan = |client: &mut Client, sealed: &Value, remote: &Value| {
        let mut args = sealed.clone();
        args["remote"] = remote.clone();
        ok(client.call("planConflict", &args.to_string()))
    };

    // Edited elsewhere earlier: ours wins, theirs is kept as a copy.
    let mut theirs = login("Bank", "https://bank.example", "theirs", 3);
    theirs.0.updated_at = 500;
    let remote = row(&server, "i1", 6, 3, &theirs);
    let answer = plan(&mut client, &ours, &remote);
    assert_eq!(answer["plan"], "overwrite");
    let body = &answer["body"];
    assert!(body["enc_tombstone"].is_null());
    let written = server.vault_key.open_overview(VAULT, "i1", body["enc_overview"].as_str().unwrap()).unwrap();
    assert_eq!(written.version, 4);
    let copy = &answer["copy"];
    let kept = server.vault_key.open_overview(VAULT, copy["id"].as_str().unwrap(), copy["encOverview"].as_str().unwrap()).unwrap();
    assert_eq!(kept.title, "Bank (conflicted copy)");
    let kept_details = server.vault_key.open_details(VAULT, copy["id"].as_str().unwrap(), copy["encDetails"].as_str().unwrap()).unwrap();
    assert_eq!(kept_details.password(), Some("theirs"));

    // Edited elsewhere later: theirs stays, ours becomes the copy.
    theirs.0.updated_at = 5_000;
    let remote = row(&server, "i1", 6, 3, &theirs);
    let answer = plan(&mut client, &ours, &remote);
    assert_eq!(answer["plan"], "take_remote");
    let copy = &answer["copy"];
    let kept_details = server.vault_key.open_details(VAULT, copy["id"].as_str().unwrap(), copy["encDetails"].as_str().unwrap()).unwrap();
    assert_eq!(kept_details.password(), Some("ours"));

    // Deleted elsewhere: the edit survives.
    let tombstone = server.vault_key.seal_tombstone(VAULT, "i1", &Tombstone { version: 3, deleted_at: 900 }).unwrap();
    let remote = json!({ "id": "i1", "vault_id": VAULT, "enc_overview": null, "enc_details": null, "revision": 3, "seq": 6, "deleted_at": "2026-10-14T00:00:00Z", "enc_tombstone": tombstone });
    let answer = plan(&mut client, &ours, &remote);
    assert_eq!(answer["plan"], "overwrite");
    assert!(answer["copy"].is_null());
    let written = server.vault_key.open_details(VAULT, "i1", answer["body"]["enc_details"].as_str().unwrap()).unwrap();
    assert_eq!(written.password(), Some("ours"));

    // Deleted here, edited elsewhere: the edit survives.
    let deletion = ok(client.call("sealTombstone", &json!({ "id": "i1", "now": 1_000 }).to_string()));
    let remote = row(&server, "i1", 6, 3, &theirs);
    let answer = plan(&mut client, &deletion, &remote);
    assert_eq!(answer["plan"], "take_remote");
    assert!(answer["copy"].is_null());

    // A forged copy on the server: ours goes over it as sent.
    let forged = json!({ "id": "i1", "vault_id": VAULT, "enc_overview": "garbage", "enc_details": "garbage", "revision": 3, "seq": 6, "deleted_at": null, "enc_tombstone": null });
    let answer = plan(&mut client, &ours, &forged);
    assert_eq!(answer["plan"], "overwrite");
    assert_eq!(answer["body"]["enc_overview"], ours["encOverview"]);
}

#[test]
fn edits_drafts_like_the_desktop() {
    let server = server();
    let mut client = signed_in(&server);
    let draft = json!({
        "vaultId": VAULT,
        "title": " Mail ",
        "category": "login",
        "urls": [{ "href": "mail.example" }],
        "tags": ["b", "a", "A"],
        "fields": [
            { "id": "", "label": "username", "kind": "text", "value": "me", "purpose": "username" },
            { "id": "", "label": "password", "kind": "concealed", "value": "first", "purpose": "password" }
        ],
        "notes": "hi"
    });
    let sealed = ok(client.call("saveDraft", &json!({ "draft": draft, "now": 100 }).to_string()));
    assert!(sealed["baseRevision"].is_null());
    let id = sealed["id"].as_str().unwrap().to_string();
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [stored(&sealed, 1, 30)] }).to_string()));

    let mut editing = ok(client.call("draftOf", &json!({ "id": id }).to_string()));
    assert_eq!(editing["title"], "Mail");
    assert_eq!(editing["urls"][0]["href"], "https://mail.example");
    assert_eq!(editing["tags"], json!(["a", "b"]));
    assert_eq!(editing["fields"][1]["id"].as_str().unwrap().len(), 12);
    editing["fields"][1]["value"] = json!("second");
    let sealed = ok(client.call("saveDraft", &json!({ "draft": editing, "now": 200 }).to_string()));
    assert_eq!(sealed["baseRevision"], 1);
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [stored(&sealed, 2, 31)] }).to_string()));
    let item = ok(client.call("item", &json!({ "id": id }).to_string()));
    assert_eq!(item["details"]["password_history"][0]["value"], "first");
    assert_eq!(item["overview"]["created_at"], 100);

    // Favorite, then Recently Deleted and back.
    let sealed = ok(client.call("setFlags", &json!({ "id": id, "favorite": true, "trashed": true, "now": 300 }).to_string()));
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [stored(&sealed, 3, 32)] }).to_string()));
    let item = ok(client.call("item", &json!({ "id": id }).to_string()));
    assert_eq!(item["overview"]["favorite"], true);
    assert_eq!(item["overview"]["trashed_at"], 300);
    let sealed = ok(client.call("setFlags", &json!({ "id": id, "trashed": false, "now": 400 }).to_string()));
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [stored(&sealed, 4, 33)] }).to_string()));
    assert!(ok(client.call("item", &json!({ "id": id }).to_string()))["overview"].get("trashed_at").is_none());

    // A copy, without the history.
    let copy = ok(client.call("duplicate", &json!({ "id": id, "title": "Mail copy", "now": 500 }).to_string()));
    assert_ne!(copy["id"], json!(id));
    assert!(copy["baseRevision"].is_null());
    let opened = server.vault_key.open_details(VAULT, copy["id"].as_str().unwrap(), copy["encDetails"].as_str().unwrap()).unwrap();
    assert_eq!(opened.password(), Some("second"));
    assert!(opened.password_history.is_empty());

    // Limits come from the shared rules.
    let long = json!({ "vaultId": VAULT, "title": "t".repeat(600), "category": "login" });
    assert_eq!(error(client.call("saveDraft", &json!({ "draft": long, "now": 1 }).to_string())), "title_too_long");
}

#[test]
fn approves_a_new_device_and_lists_devices() {
    let server = server();
    let mut approver = signed_in(&server);
    let mut asker = Client::new();
    let started = ok(asker.call("setupStart", ""));
    let answer = ok(approver.call("approvalStart", &json!({ "id": "r1", "publicKey": started["publicKey"], "commitment": started["commitment"] }).to_string()));
    let shown = ok(asker.call("setupCode", &json!({ "approverKey": answer["publicKey"], "approverNonce": answer["nonce"] }).to_string()));
    let typed = |code: &str| json!({ "id": "r1", "nonce": shown["nonce"], "code": code, "secretKey": server.secret_key }).to_string();
    assert_eq!(error(approver.call("approvalSeal", &typed("000000"))), "device_setup_code_wrong");
    let envelope = ok(approver.call("approvalSeal", &typed(shown["code"].as_str().unwrap())));
    let opened = ok(asker.call("setupOpen", &json!({ "requestId": "r1", "approverKey": answer["publicKey"], "approverNonce": answer["nonce"], "payload": envelope }).to_string()));
    assert_eq!(opened["email"], "me@example.com");
    assert_eq!(opened["secretKey"], json!(server.secret_key));

    // Three wrong codes: the request has to be refused.
    let started = ok(asker.call("setupStart", ""));
    let answer = ok(approver.call("approvalStart", &json!({ "id": "r2", "publicKey": started["publicKey"], "commitment": started["commitment"] }).to_string()));
    let shown = ok(asker.call("setupCode", &json!({ "approverKey": answer["publicKey"], "approverNonce": answer["nonce"] }).to_string()));
    let wrong = json!({ "id": "r2", "nonce": shown["nonce"], "code": "111111", "secretKey": server.secret_key }).to_string();
    assert_eq!(error(approver.call("approvalSeal", &wrong)), "device_setup_code_wrong");
    assert_eq!(error(approver.call("approvalSeal", &wrong)), "device_setup_code_wrong");
    assert_eq!(error(approver.call("approvalSeal", &wrong)), "device_setup_code_denied");
    assert_eq!(error(approver.call("approvalSeal", &wrong)), "device_setup_expired");

    // What a device says about itself, read back by another one.
    let sealed = ok(approver.call("deviceInfo", &json!({ "deviceId": "d1", "name": "Pixel", "platform": "android", "os": "Android 15", "appVersion": "0.1.9" }).to_string()));
    let rows = json!([{ "id": "d1", "enc_info": sealed, "ip": "1.2.3.4" }, { "id": "d2", "enc_info": sealed }]);
    let list = ok(approver.call("deviceList", &rows.to_string()));
    assert_eq!(list[0]["name"], "Pixel");
    assert_eq!(list[0]["platform"], "android");
    assert_eq!(list[0]["ip"], "1.2.3.4");
    assert!(list[0].get("enc_info").is_none());
    // Sealed for another device id: not shown as that device.
    assert_eq!(list[1]["name"], "");
}

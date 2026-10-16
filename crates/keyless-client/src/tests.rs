use keyless_core::{
    account::create_account,
    crypto::SymmetricKey,
    health::ChecksKey,
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

    // The item shows it (without its private key), and it can be removed.
    let shown = ok(client.call("item", &json!({ "id": item["id"] }).to_string()));
    assert_eq!(shown["details"]["passkeys"][0]["rpId"], "example.com");
    assert!(shown["details"]["passkeys"][0].get("key").is_none());
    let removed = ok(client.call("passkeyRemove", &json!({ "itemId": item["id"], "credentialId": made["credentialId"], "now": 20 }).to_string()));
    assert_eq!(removed["baseRevision"], 1);
    let details = server.vault_key.open_details(VAULT, item["id"].as_str().unwrap(), removed["encDetails"].as_str().unwrap()).unwrap();
    assert!(details.passkeys.is_empty());
    assert_eq!(error(client.call("passkeyRemove", &json!({ "itemId": item["id"], "credentialId": "other", "now": 20 }).to_string())), "not_found");
}

#[test]
fn generates_passwords() {
    let mut client = Client::new();
    let random = ok(client.call("generate", &json!({ "kind": "random", "length": 20 }).to_string()));
    assert_eq!(random["password"].as_str().unwrap().chars().count(), 20);
    let pin = ok(client.call("generate", &json!({ "kind": "pin", "length": 6 }).to_string()));
    assert!(pin["password"].as_str().unwrap().chars().all(|c| c.is_ascii_digit()));
    // Not "-": a few words have a hyphen of their own ("t-shirt").
    let words = ok(client.call("generate", &json!({ "kind": "memorable", "words": 4, "separator": "." }).to_string()));
    assert_eq!(words["password"].as_str().unwrap().split('.').count(), 4);
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

#[test]
fn signs_in_with_a_qr_code() {
    let server = server();
    let mut phone = signed_in(&server);
    let mut asker = Client::new();
    let started = ok(asker.call("signInStart", ""));
    let link = started["link"].as_str().unwrap();
    assert!(link.starts_with("keyless://sign-in#"));
    assert!(!link.contains(started["secret"].as_str().unwrap()));
    // A signed-out or locked phone reads the code but cannot answer it.
    assert_eq!(ok(Client::new().call("signInLink", &json!({ "text": link }).to_string()))["id"], started["id"]);
    assert_eq!(error(Client::new().call("signInSeal", &json!({ "text": link, "secretKey": server.secret_key }).to_string())), "locked");
    assert_eq!(error(phone.call("signInLink", &json!({ "text": "keyless://setup#email=a" }).to_string())), "sign_in_code_invalid");

    let sealed = ok(phone.call("signInSeal", &json!({ "text": link, "secretKey": server.secret_key }).to_string()));
    assert_eq!(sealed["id"], started["id"]);
    let opened = ok(asker.call("signInOpen", &json!({ "approverKey": sealed["approverKey"], "payload": sealed["payload"] }).to_string()));
    assert_eq!(opened["email"], "me@example.com");
    assert_eq!(opened["secretKey"], json!(server.secret_key));
    // Opened once.
    assert_eq!(error(asker.call("signInOpen", &json!({ "approverKey": sealed["approverKey"], "payload": sealed["payload"] }).to_string())), "device_setup_expired");

    // An answer for another request does not open.
    ok(asker.call("signInStart", ""));
    assert_eq!(error(asker.call("signInOpen", &json!({ "approverKey": sealed["approverKey"], "payload": sealed["payload"] }).to_string())), "device_setup_failed");
}

#[test]
fn keeps_site_icons_sealed() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let server = server();
    let mut client = signed_in(&server);
    assert_eq!(error(Client::new().call("siteIconHosts", "")), "locked");
    const A: &str = "33333333-3333-4333-8333-333333333333";
    const B: &str = "44444444-4444-4444-8444-444444444444";
    let items = json!([row(&server, A, 5, 1, &login("GitHub", "https://www.github.com/login", "pw1", 1)), row(&server, B, 6, 1, &login("Bank", "https://bank.example", "pw2", 1))]);
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": items }).to_string()));
    // Only public names (bank.example is not one), named by a hash.
    let hosts = ok(client.call("siteIconHosts", ""));
    assert_eq!(hosts.as_array().unwrap().len(), 1);
    assert_eq!(hosts[0]["host"], "github.com");
    let id = hosts[0]["id"].as_str().unwrap().to_string();
    assert!(!id.contains("github"));

    let sealed = ok(client.call("siteIconSeal", &json!({ "id": id, "png": STANDARD.encode(b"a png"), "opaque": false }).to_string()));
    let opened = ok(client.call("siteIconOpen", &json!({ "id": id, "data": sealed }).to_string()));
    assert_eq!(opened["png"], STANDARD.encode(b"a png"));
    assert_eq!(opened["padded"], true);
    let none = ok(client.call("siteIconSeal", &json!({ "id": id }).to_string()));
    assert_eq!(ok(client.call("siteIconOpen", &json!({ "id": id, "data": none }).to_string())), Value::Null);

    let links = ok(client.call("siteIconLinks", &json!({ "html": "<head><link rel=icon href=/a.png sizes=64x64></head>", "url": "https://github.com/" }).to_string()));
    assert_eq!(links, json!(["https://github.com/a.png"]));
    assert_eq!(ok(Client::new().call("siteIconAllowed", &json!({ "host": "router.lan" }).to_string())), json!(false));
    assert_eq!(ok(Client::new().call("siteIconAllowed", &json!({ "host": "github.com" }).to_string())), json!(true));
    for (ip, public) in [("10.0.0.1", false), ("[::1]", false), ("192.168.1.10", false), ("140.82.112.3", true)] {
        assert_eq!(ok(Client::new().call("publicAddress", &json!({ "ip": ip }).to_string())), json!(public), "{ip}");
    }
}

/// A public list as the host downloads it: `sites`, and enough others to
/// read as the real one.
fn list_body(kind: &str, sites: &[&str]) -> String {
    let domains: Vec<String> = sites.iter().map(|s| s.to_string()).chain((0..300).map(|i| format!("site{i}.example"))).collect();
    let list: Value = match kind {
        "breaches" => domains
            .iter()
            .map(|d| json!({ "Title": d, "Domain": d, "BreachDate": "2020-01-01", "PwnCount": 7, "DataClasses": ["Email addresses", "Passwords"], "IsVerified": true }))
            .collect(),
        "twoFactor" => domains.iter().map(|d| json!([d, { "domain": d }])).collect(),
        _ => domains.iter().map(|d| (d.clone(), json!({ "passwordless": "allowed" }))).collect::<serde_json::Map<_, _>>().into(),
    };
    list.to_string()
}

#[test]
fn sentinel_reports_like_the_desktop() {
    let server = server();
    let mut client = signed_in(&server);
    // Weak and reused; also on plain http; strong, without one-time codes.
    let mut alone = login("Alone", "https://github.com/login", "x$7Lq!92mZ@pR4#vN8&kT1", 1);
    alone.1.fields.retain(|f| f.kind != FieldKind::Totp);
    let items = json!([
        row(&server, "a", 5, 1, &login("Mail", "https://mail.example", "password", 1)),
        row(&server, "b", 6, 1, &login("Bank", "http://bank.example", "password", 1)),
        row(&server, "c", 7, 1, &alone),
    ]);
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": items }).to_string()));

    // Nothing downloaded or checked online yet.
    let report = ok(client.call("sentinelReport", &json!({ "lists": null, "now": 1_000 }).to_string()));
    assert_eq!(report["checked"], 3);
    assert_eq!(report["pending"], json!(["breached", "compromised", "two_factor", "passkey"]));
    assert_eq!(report["unchecked"], 3);
    assert_eq!(report["weak"], json!(["a", "b"]));
    assert_eq!(report["reused"].as_array().unwrap().len(), 1);
    assert_eq!(report["unsecured"], json!(["b"]));
    assert_eq!(report["httpsReady"], json!(["b"]));
    assert_eq!(report["strengths"][VAULT][0], 2);
    let summary = &report["summary"];
    assert!(summary["vaultId"].is_null());
    assert_eq!((summary["checked"].as_u64(), summary["score"].as_u64()), (Some(3), Some(33)));
    assert_eq!(summary["issues"]["reused"][0]["others"], 1);

    // The lists, as downloaded and read; one too small is a broken download.
    let listed = ok(client.call("sentinelLists", ""));
    assert_eq!(listed.as_array().unwrap().iter().map(|l| l["kind"].as_str().unwrap()).collect::<Vec<_>>(), ["breaches", "twoFactor", "passkeys"]);
    assert_eq!(listed[0]["url"], "https://haveibeenpwned.com/api/v3/breaches");
    assert_eq!(error(client.call("sentinelParseList", &json!({ "kind": "passkeys", "body": "{\"github.com\": {}}" }).to_string())), "sentinel_list_invalid");
    assert_eq!(error(client.call("sentinelParseList", &json!({ "kind": "breaches", "body": "<html>maintenance</html>" }).to_string())), "sentinel_list_invalid");
    let parse = |client: &mut Client, kind: &str, sites: &[&str]| ok(client.call("sentinelParseList", &json!({ "kind": kind, "body": list_body(kind, sites) }).to_string()))["sites"].clone();
    let breaches = parse(&mut client, "breaches", &["bank.example"]);
    assert_eq!(breaches["bank.example"], json!({ "date": "2020-01-01", "breach": { "title": "bank.example", "dataClasses": ["Email addresses", "Passwords"], "accounts": 7 } }));
    let lists = json!({
        "breaches": { "sites": breaches, "fetchedAt": 900 },
        "twoFactor": { "sites": parse(&mut client, "twoFactor", &["github.com"]), "fetchedAt": 800 },
        "passkeys": { "sites": parse(&mut client, "passkeys", &["accounts.mail.example"]), "fetchedAt": 950 },
    });
    let report = ok(client.call("sentinelReport", &json!({ "lists": lists, "now": 1_000 }).to_string()));
    assert_eq!(report["pending"], json!(["breached"]));
    assert_eq!(report["listsUpdatedAt"], 800);
    assert_eq!(report["compromised"][0]["id"], "b");
    assert_eq!(report["compromised"][0]["date"], "2020-01-01");
    assert_eq!(report["twoFactor"], json!([{ "id": "c", "site": "github.com" }]));
    assert_eq!(report["passkeys"], json!([{ "id": "a", "site": "mail.example" }]));
    assert_eq!(report["summary"]["issues"]["compromised"][0]["breach"]["accounts"], 7);

    // A list turned off: its alert is off rather than pending; one turned
    // on but never downloaded leaves the lists' age unknown.
    let some = json!({ "breaches": lists["breaches"], "twoFactor": null });
    let report = ok(client.call("sentinelReport", &json!({ "lists": some, "off": ["passkeys"], "now": 1_000 }).to_string()));
    assert_eq!(report["off"], json!(["passkey"]));
    assert_eq!(report["pending"], json!(["breached", "two_factor"]));
    assert!(report["passkeys"].as_array().unwrap().is_empty());
    assert!(report["listsUpdatedAt"].is_null());

    // One vault, while the account has it; every vault otherwise.
    let report = ok(client.call("sentinelReport", &json!({ "lists": lists, "vaultId": VAULT, "now": 1_000 }).to_string()));
    assert_eq!(report["summary"]["vaultId"], VAULT);
    assert_eq!(report["summary"]["checked"], 3);
    let report = ok(client.call("sentinelReport", &json!({ "lists": lists, "vaultId": "elsewhere", "now": 1_000 }).to_string()));
    assert!(report["summary"]["vaultId"].is_null());

    ok(client.call("lock", ""));
    assert_eq!(error(client.call("sentinelReport", &json!({ "now": 1_000 }).to_string())), "locked");
}

#[test]
fn sentinel_checks_breached_passwords_like_the_desktop() {
    let server = server();
    let mut client = signed_in(&server);
    let items = json!([
        row(&server, "a", 5, 1, &login("Mail", "https://mail.example", "password", 1)),
        row(&server, "b", 6, 1, &login("Bank", "https://bank.example", "Zq8!vT3#mW9$kL2@-only-here", 1)),
    ]);
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": items }).to_string()));

    // Only the first 5 characters of each password's SHA-1 hash are asked
    // about: SHA-1("password") is 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.
    let queries = ok(client.call("sentinelBreachQueries", &json!({ "now": 1_000 }).to_string()));
    assert_eq!((queries["all"].as_bool(), queries["upToDate"].as_bool()), (Some(true), Some(false)));
    let prefixes: Vec<String> = queries["prefixes"].as_array().unwrap().iter().map(|p| p.as_str().unwrap().to_string()).collect();
    assert_eq!(prefixes.len(), 2);
    assert!(prefixes.contains(&"5BAA6".to_string()) && prefixes.iter().all(|p| p.len() == 5));

    // The range API's padded answers.
    let responses: serde_json::Map<String, Value> = prefixes
        .iter()
        .map(|p| {
            let body = if p == "5BAA6" { "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n" } else { "00000000000000000000000000000000000:3\r\n" };
            (p.to_lowercase(), json!(body))
        })
        .collect();
    let results = ok(client.call("sentinelBreachResults", &json!({ "all": true, "responses": responses, "now": 1_000 }).to_string()));
    assert_eq!((results["checked"].as_u64(), results["breached"].as_u64(), results["checkedAt"].as_i64()), (Some(2), Some(1), Some(1_000)));
    let checks = results["checks"].as_str().unwrap().to_string();

    // Kept encrypted the desktop's way: its key comes from the user key.
    assert!(checks.starts_with("k1."));
    let user_key = URL_SAFE_NO_PAD.decode(ok(client.call("exportUserKey", "")).as_str().unwrap()).unwrap();
    let key = ChecksKey::new(&SymmetricKey::from_slice(&user_key).unwrap()).unwrap();
    let kept = key.open_checks(Some(&checks));
    assert_eq!((kept.checked_at, kept.seen.len(), kept.seen[&key.id("password")]), (Some(1_000), 2, 9_545_824));

    let report = ok(client.call("sentinelReport", &json!({ "checks": checks, "now": 1_100 }).to_string()));
    assert_eq!(report["breached"], json!([["a", 9_545_824]]));
    assert_eq!(report["unchecked"], 0);
    assert_eq!(report["passwordsCheckedAt"], 1_000);
    assert_eq!(report["pending"], json!(["compromised", "two_factor", "passkey"]));

    // The next automatic check, before a day passed: nothing to ask.
    let queries = ok(client.call("sentinelBreachQueries", &json!({ "checks": checks, "maxAge": 86_400, "now": 2_000 }).to_string()));
    assert_eq!((queries["all"].as_bool(), queries["upToDate"].as_bool()), (Some(false), Some(true)));
    assert_eq!(queries["prefixes"], json!([]));
    // A day later: every password again.
    let queries = ok(client.call("sentinelBreachQueries", &json!({ "checks": checks, "maxAge": 86_400, "now": 1_000 + 86_400 }).to_string()));
    assert_eq!(queries["all"], true);

    // A new password: only it is asked about, and an answer missing leaves
    // it unchecked.
    let added = login("New", "https://new.example", "brand-new-W4!-pass", 1);
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [row(&server, "c", 7, 1, &added)] }).to_string()));
    let queries = ok(client.call("sentinelBreachQueries", &json!({ "checks": checks, "maxAge": 86_400, "now": 2_000 }).to_string()));
    assert_eq!((queries["all"].as_bool(), queries["prefixes"].as_array().unwrap().len()), (Some(false), 1));
    let results = ok(client.call("sentinelBreachResults", &json!({ "checks": checks, "all": false, "responses": {}, "now": 2_000 }).to_string()));
    let report = ok(client.call("sentinelReport", &json!({ "checks": results["checks"], "now": 2_000 }).to_string()));
    assert_eq!((report["unchecked"].as_u64(), report["passwordsCheckedAt"].as_i64()), (Some(1), Some(1_000)));

    // Results that do not open (another account's): nothing checked.
    let report = ok(client.call("sentinelReport", &json!({ "checks": "k1.AAAA", "now": 2_000 }).to_string()));
    assert_eq!(report["unchecked"], 3);
    assert_eq!(report["pending"][0], "breached");
}

#[test]
fn sentinel_edits_like_the_desktop() {
    let server = server();
    // Before signing in: the master password's strength, and nothing about
    // items.
    let mut client = Client::new();
    let weak = ok(client.call("strength", &json!({ "password": "password" }).to_string()));
    assert_eq!((weak["level"].as_u64(), weak["score"].as_u64()), (Some(0), Some(0)));
    assert!(weak["reused"].is_null());
    assert_eq!(ok(client.call("strength", &json!({ "password": "8]bz-Pv&wu~AO5uEF?f{Uec>" }).to_string()))["level"], 6);
    // The account's own words make it weaker.
    let plain = ok(client.call("strength", &json!({ "password": "zorblaxquintel2024" }).to_string()));
    let own = ok(client.call("strength", &json!({ "password": "zorblaxquintel2024", "inputs": ["zorblaxquintel"] }).to_string()));
    assert!(own["guessesLog10"].as_f64().unwrap() < plain["guessesLog10"].as_f64().unwrap());

    let mut client = signed_in(&server);
    let mut trashed = login("Old", "http://old.example", "Hn4#pX8!rT2$wQ6@", 1);
    trashed.0.trashed_at = Some(5);
    let items = json!([
        row(&server, "a", 5, 1, &login("Mail", "http://mail.example", "password", 1)),
        row(&server, "b", 6, 1, &login("Bank", "https://bank.example", "password", 1)),
        row(&server, "c", 7, 1, &trashed),
    ]);
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": items }).to_string()));
    // The editor's check: the other items with the same password (not those
    // in Recently Deleted).
    assert_eq!(ok(client.call("strength", &json!({ "password": "password" }).to_string()))["reused"], 2);
    assert_eq!(ok(client.call("strength", &json!({ "password": "password", "itemId": "a" }).to_string()))["reused"], 1);
    assert_eq!(ok(client.call("strength", &json!({ "password": "Hn4#pX8!rT2$wQ6@" }).to_string()))["reused"], 0);

    // Ignoring alerts: a new version of the item, and they leave their lists.
    assert_eq!(error(client.call("sentinelIgnore", &json!({ "id": "a", "alerts": ["nonsense"], "ignored": true, "now": 10 }).to_string())), "invalid_request");
    let sealed = ok(client.call("sentinelIgnore", &json!({ "id": "a", "alerts": ["weak", "reused"], "ignored": true, "now": 10 }).to_string()));
    assert_eq!(sealed["baseRevision"], 1);
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [stored(&sealed, 2, 8)] }).to_string()));
    let report = ok(client.call("sentinelReport", &json!({ "now": 20 }).to_string()));
    assert_eq!(report["weak"], json!(["b"]));
    assert_eq!(report["ignored"], json!([["a", "weak"], ["a", "reused"]]));
    // Still grouped: the other item still shares the password.
    assert_eq!(report["summary"]["issues"]["reused"], json!([{ "id": "b", "others": 1 }]));

    // "Use HTTPS", saved like any edit; the ignored alerts stay.
    let sealed = ok(client.call("sentinelUseHttps", &json!({ "id": "a", "now": 30 }).to_string()));
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [stored(&sealed, 3, 9)] }).to_string()));
    let item = ok(client.call("item", &json!({ "id": "a" }).to_string()));
    assert_eq!(item["overview"]["urls"][0]["href"], "https://mail.example");
    assert_eq!(item["overview"]["sentinel_ignored"], json!(["weak", "reused"]));
    assert_eq!(error(client.call("sentinelUseHttps", &json!({ "id": "a", "now": 40 }).to_string())), "https_unavailable");
    // Saving an item in Recently Deleted would restore it.
    assert_eq!(error(client.call("sentinelUseHttps", &json!({ "id": "c", "now": 40 }).to_string())), "https_trashed");

    // Watched again.
    let sealed = ok(client.call("sentinelIgnore", &json!({ "id": "a", "alerts": ["weak"], "ignored": false, "now": 50 }).to_string()));
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [stored(&sealed, 4, 10)] }).to_string()));
    assert_eq!(ok(client.call("sentinelReport", &json!({ "now": 60 }).to_string()))["ignored"], json!([["a", "reused"]]));
}

#[test]
fn shows_and_restores_earlier_versions() {
    let server = server();
    let mut client = signed_in(&server);
    let first = login("Bank", "https://bank.example", "one", 1);
    let second = login("Bank", "https://bank.example", "two", 2);
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [row(&server, "i1", 5, 2, &second)] }).to_string()));
    // What the server kept when the second write replaced the first; and a
    // forged row, and one claiming to be newer, which are left out.
    let kept = |item: &(ItemOverview, ItemDetails), revision: i64| {
        json!({ "revision": revision, "enc_overview": server.vault_key.seal_overview(VAULT, "i1", &item.0).unwrap(), "enc_details": server.vault_key.seal_details(VAULT, "i1", &item.1).unwrap() })
    };
    let rows = json!([kept(&first, 1), { "revision": 0, "enc_overview": "x", "enc_details": "y" }, kept(&login("Bank", "https://bank.example", "later", 9), 3)]);
    let versions = ok(client.call("itemVersions", &json!({ "id": "i1", "rows": rows }).to_string()));
    assert_eq!(versions.as_array().unwrap().len(), 1);
    assert_eq!(versions[0]["revision"], 1);
    assert_eq!(versions[0]["changed"], json!(["password"]));

    let sealed = ok(client.call("restoreVersion", &json!({ "id": "i1", "rows": rows, "revision": 1, "now": 500 }).to_string()));
    assert_eq!(sealed["baseRevision"], 2);
    let restored = server.vault_key.open_details(VAULT, "i1", sealed["encDetails"].as_str().unwrap()).unwrap();
    assert_eq!(restored.password(), Some("one"));
    assert_eq!(restored.password_history[0].value, "two");
    let overview = server.vault_key.open_overview(VAULT, "i1", sealed["encOverview"].as_str().unwrap()).unwrap();
    assert_eq!(overview.version, 3);
    assert_eq!(error(client.call("restoreVersion", &json!({ "id": "i1", "rows": rows, "revision": 7, "now": 500 }).to_string())), "not_found");
}

#[test]
fn makes_and_lists_share_links() {
    let server = server();
    let mut client = signed_in(&server);
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [row(&server, "i1", 5, 1, &login("Bank", "https://bank.example", "pw", 1))] }).to_string()));
    let made = ok(client.call(
        "shareCreate",
        &json!({ "itemId": "i1", "hours": 24, "viewOnce": true, "recipients": [" Ana@Example.com", "ana@example.com"], "base": "https://k.test/share/", "now": 1_791_400_506 }).to_string(),
    ));
    let link = made["link"].as_str().unwrap();
    assert!(link.starts_with("https://k.test/share/#"));
    let row = &made["row"];
    assert_eq!(row["max_views"], 1);
    assert_eq!(row["expires_at"], "2026-10-08T19:15:06Z");
    assert_eq!(row["recipients"].as_array().unwrap().len(), 1);
    // The page opens the snapshot with the link's key.
    let key = keyless_core::share::ShareKey::from_fragment(link.split_once('#').unwrap().1).unwrap();
    assert_eq!(key.open(row["enc_payload"].as_str().unwrap()).unwrap().title, "Bank");
    assert_eq!(error(client.call("shareCreate", &json!({ "itemId": "i1", "hours": 5, "base": "x", "now": 1 }).to_string())), "share_duration");

    let listed = |client: &mut Client, all: bool, now: i64| {
        let rows = json!([
            { "id": row["id"], "enc_label": row["enc_label"], "created_at": "2026-10-07T19:15:06Z", "expires_at": row["expires_at"], "views": 0, "max_views": 1 },
            { "id": "someone-else", "enc_label": "x", "created_at": "2026-10-07T19:15:06Z", "expires_at": row["expires_at"] },
        ]);
        ok(client.call("shareList", &json!({ "rows": rows, "all": all, "now": now }).to_string()))
    };
    let active = listed(&mut client, false, 1_791_400_506);
    assert_eq!(active.as_array().unwrap().len(), 1);
    assert_eq!(active[0]["title"], "Bank");
    assert_eq!(active[0]["status"], "active");
    assert_eq!(active[0]["recipients"], json!(["ana@example.com"]));
    // A day later it ended: only listed with `all`.
    assert!(listed(&mut client, false, 1_791_500_000).as_array().unwrap().is_empty());
    assert_eq!(listed(&mut client, true, 1_791_500_000)[0]["status"], "expired");
}

#[test]
fn searches_inside_items_but_not_secrets() {
    let server = server();
    let mut client = signed_in(&server);
    let draft = json!({
        "vaultId": VAULT, "title": "Router", "category": "wireless_router", "notes": "Family plan",
        "fields": [
            { "id": "", "label": "network name", "kind": "text", "value": "Casa da Mãe" },
            { "id": "", "label": "wireless password", "kind": "concealed", "value": "hunter22", "purpose": "password" }
        ]
    });
    let sealed = ok(client.call("saveDraft", &json!({ "draft": draft, "now": 10 }).to_string()));
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [stored(&sealed, 1, 40)] }).to_string()));
    let id = sealed["id"].clone();
    let search = |client: &mut Client, query: &str| ok(client.call("searchDetails", &json!({ "query": query }).to_string()));
    assert_eq!(search(&mut client, "FAMILY"), json!([id]));
    assert_eq!(search(&mut client, "casa"), json!([id]));
    // Case and accents aside, both ways.
    assert_eq!(search(&mut client, "da mae"), json!([id]));
    assert_eq!(search(&mut client, "MÃE"), json!([id]));
    assert_eq!(search(&mut client, "hunter"), json!([]));
    assert_eq!(search(&mut client, "c"), json!([]));
    let qr = ok(client.call("wifiQr", &json!({ "id": id }).to_string()));
    assert!(qr.as_array().unwrap().len() >= 21);
    assert_eq!(ok(client.call("itemsWithPasskeys", "")), json!([]));
}

#[test]
fn keeps_files_in_items_without_showing_their_keys() {
    use keyless_core::attachment::CHUNK_SIZE;
    let server = server();
    let mut client = signed_in(&server);
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [row(&server, "i1", 5, 1, &login("Bank", "https://bank.example", "pw", 1))] }).to_string()));

    let size = CHUNK_SIZE + 10;
    let new = ok(client.call("attachmentNew", &json!({ "name": "../scan.pdf", "size": size, "vaultId": VAULT, "now": 100 }).to_string()));
    assert!(new.get("key").is_none());
    assert_eq!(new["name"], "scan.pdf");
    assert_eq!(new["chunks"], 2);
    assert_eq!(new["chunkLens"], json!([CHUNK_SIZE, 10]));
    let id = new["id"].as_str().unwrap().to_string();
    assert_eq!(new["objects"][1], format!("{VAULT}/{id}/1"));
    assert_eq!(new["stored"], size as u64 + 2 * 40);

    let plain = [vec![7u8; CHUNK_SIZE], vec![9u8; 10]];
    let raw: Vec<Vec<u8>> = (0..2).map(|i| client.attachment_seal(&id, i, &plain[i as usize]).unwrap()).collect();
    assert_eq!(client.attachment_seal(&id, 1, &[1, 2]).unwrap_err().key, "file_changed");
    assert_eq!(client.attachment_seal("nope", 0, &[]).unwrap_err().key, "not_found");

    let sealed = ok(client.call("attachmentsAdd", &json!({ "itemId": "i1", "ids": [id], "now": 200 }).to_string()));
    assert_eq!(sealed["baseRevision"], 1);
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [stored(&sealed, 2, 6)] }).to_string()));
    // Added once: the pending file is gone.
    assert_eq!(error(client.call("attachmentsAdd", &json!({ "itemId": "i1", "ids": [id], "now": 200 }).to_string())), "not_found");

    let listed = ok(client.call("attachments", &json!({ "itemId": "i1" }).to_string()));
    assert_eq!(listed[0]["name"], "scan.pdf");
    assert!(listed[0].get("key").is_none());
    let item = ok(client.call("item", &json!({ "id": "i1" }).to_string()));
    assert_eq!(item["details"]["attachments"][0]["size"], size);
    assert!(item["details"]["attachments"][0].get("key").is_none());

    assert_eq!(*client.attachment_open("i1", &id, 1, &raw[1]).unwrap(), plain[1]);
    // A chunk in the wrong place, or changed, does not open.
    assert_eq!(client.attachment_open("i1", &id, 0, &raw[1]).unwrap_err().key, "attachment_damaged");
    let mut changed = raw[0].clone();
    changed[30] ^= 1;
    assert_eq!(client.attachment_open("i1", &id, 0, &changed).unwrap_err().key, "attachment_damaged");

    let removed = ok(client.call("attachmentRemove", &json!({ "itemId": "i1", "attachmentId": id, "now": 300 }).to_string()));
    assert_eq!(removed["objects"], json!([format!("{VAULT}/{id}/0"), format!("{VAULT}/{id}/1")]));
    let details = server.vault_key.open_details(VAULT, "i1", removed["encDetails"].as_str().unwrap()).unwrap();
    assert!(details.attachments.is_empty());

    // "Save in Keyless": a Document item holding the file.
    let new = ok(client.call("attachmentNew", &json!({ "name": "id card.jpg", "size": 3, "vaultId": VAULT, "now": 400 }).to_string()));
    let id = new["id"].as_str().unwrap().to_string();
    let made = ok(client.call("documentNew", &json!({ "id": id, "label": "document", "now": 400 }).to_string()));
    assert!(made["baseRevision"].is_null());
    let item_id = made["id"].as_str().unwrap();
    let overview = server.vault_key.open_overview(VAULT, item_id, made["encOverview"].as_str().unwrap()).unwrap();
    assert_eq!((overview.title.as_str(), overview.category), ("id card.jpg", Category::Document));
    let details = server.vault_key.open_details(VAULT, item_id, made["encDetails"].as_str().unwrap()).unwrap();
    assert_eq!((details.fields[0].kind, details.fields[0].value.as_str()), (FieldKind::File, id.as_str()));
    assert_eq!(details.attachments[0].id, id);

    let new = ok(client.call("attachmentNew", &json!({ "name": "x", "size": 1, "vaultId": VAULT, "now": 500 }).to_string()));
    ok(client.call("attachmentForget", &json!({ "id": new["id"] }).to_string()));
    assert_eq!(error(client.call("documentNew", &json!({ "id": new["id"], "label": "document", "now": 500 }).to_string())), "not_found");
    assert_eq!(error(client.call("attachmentNew", &json!({ "name": "x", "size": 1, "vaultId": "nope", "now": 500 }).to_string())), "not_found");
}

#[test]
fn makes_and_uses_recovery_keys_like_the_desktop() {
    let server = server();
    let mut client = signed_in(&server);
    let wrong = json!({ "masterPassword": "not it", "secretKey": server.secret_key });
    assert_eq!(error(client.call("recoveryCreate", &wrong.to_string())), "wrong_password");
    assert_eq!(error(client.call("checkPassword", &wrong.to_string())), "wrong_password");
    let right = json!({ "masterPassword": PASSWORD, "secretKey": server.secret_key });
    assert_eq!(ok(client.call("checkPassword", &right.to_string())), true);
    let made = ok(client.call("recoveryCreate", &right.to_string()));
    let recovery_key = made["recoveryKey"].as_str().unwrap();
    assert!(recovery_key.starts_with("KLRK-"));
    // Another account is signed in on this phone.
    assert_eq!(error(client.call("recoveryBegin", &json!({ "email": "other@example.com", "recoveryKey": recovery_key }).to_string())), "device_other_account");

    // On a phone without the account, with the key typed loosely.
    let mut phone = Client::new();
    assert_eq!(error(phone.call("recoveryBegin", &json!({ "email": "me@example.com", "recoveryKey": "KLRK-0000" }).to_string())), "recovery_key_invalid");
    let begun = ok(phone.call("recoveryBegin", &json!({ "email": " Me@Example.com", "recoveryKey": recovery_key.to_lowercase().replace('-', " ") }).to_string()));
    assert_eq!(begun["proof"], made["proof"]);
    let profile = &server.profile;
    let start = |enc: &Value| json!({ "user_id": USER, "enc_recovery_user_key": enc, "format": profile["format"], "public_key": profile["public_key"], "enc_private_key": profile["enc_private_key"] });
    assert_eq!(error(phone.call("recoveryOpen", &start(&json!("x")).to_string())), "recovery_failed");
    ok(phone.call("recoveryOpen", &start(&made["encUserKey"]).to_string()));
    assert_eq!(error(phone.call("recoveryPrepare", &json!({ "masterPassword": "short" }).to_string())), "password_too_short");
    assert_eq!(error(phone.call("recoveryPrepare", &json!({ "masterPassword": "password1234" }).to_string())), "password_weak");
    let new_password = "violet anchor drizzle 47 mosaic";
    let prepared = ok(phone.call("recoveryPrepare", &json!({ "masterPassword": new_password }).to_string()));
    let send = &prepared["send"];
    assert_eq!(send["p_email"], "me@example.com");
    assert_eq!(send["p_proof"], made["proof"]);
    assert_eq!(send["p_auth_secret"], prepared["authSecret"]);

    // The server took it; signing in opens the account with the new keys.
    let mut new_profile = profile.clone();
    new_profile["kdf"] = send["p_kdf"].clone();
    new_profile["enc_user_key"] = send["p_enc_user_key"].clone();
    let status = ok(phone.call("signedIn", &json!({ "userId": USER, "profile": new_profile }).to_string()));
    assert_eq!(status["unlocked"], true);
    ok(phone.call("applyMemberships", &server.membership.to_string()));
    assert_eq!(ok(phone.call("vaults", ""))[0]["name"], "Personal");
    // The new master password and Secret Key derive the secret just sent.
    let secret_key = prepared["show"]["secretKey"].as_str().unwrap();
    let derived = ok(Client::new().call("derive", &json!({ "email": "me@example.com", "masterPassword": new_password, "secretKey": secret_key }).to_string()));
    assert_eq!(derived["authSecret"], send["p_auth_secret"]);
    // And the next recovery key opens the account too.
    let mut later = Client::new();
    ok(later.call("recoveryBegin", &json!({ "email": "me@example.com", "recoveryKey": prepared["show"]["recoveryKey"] }).to_string()));
    ok(later.call("recoveryOpen", &start(&send["p_new_enc_recovery_user_key"]).to_string()));
    ok(later.call("recoveryForget", ""));
    assert_eq!(error(later.call("recoveryPrepare", &json!({ "masterPassword": new_password }).to_string())), "recovery_expired");
}

#[cfg(feature = "ssh")]
#[test]
fn makes_and_reads_ssh_keys() {
    let mut client = Client::new();
    let made = ok(client.call("sshGenerate", &json!({ "comment": "phone" }).to_string()));
    assert!(made["publicKey"].as_str().unwrap().starts_with("ssh-ed25519 "));
    let flattened = made["privateKey"].as_str().unwrap().replace('\n', " ");
    let read = ok(client.call("sshImport", &json!({ "privateKey": flattened }).to_string()));
    assert_eq!(read["fingerprint"], made["fingerprint"]);
    assert_eq!(error(client.call("sshImport", &json!({ "privateKey": "nope" }).to_string())), "ssh_key_invalid");
}

#[test]
fn exports_and_imports_like_the_desktop() {
    let server = server();
    let mut client = signed_in(&server);
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [row(&server, "i1", 5, 1, &login("Bank", "https://bank.example", "pw", 1))] }).to_string()));
    // A file in the item, as the server keeps it.
    let new = ok(client.call("attachmentNew", &json!({ "name": "scan.pdf", "size": 5, "vaultId": VAULT, "now": 100 }).to_string()));
    let file_id = new["id"].as_str().unwrap().to_string();
    let raw = client.attachment_seal(&file_id, 0, b"hello").unwrap();
    let sealed = ok(client.call("attachmentsAdd", &json!({ "itemId": "i1", "ids": [file_id], "now": 100 }).to_string()));
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [stored(&sealed, 2, 6)] }).to_string()));

    let password = |extra: Value| {
        let mut args = json!({ "masterPassword": PASSWORD, "secretKey": server.secret_key, "now": 200 });
        args.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        args.to_string()
    };
    assert_eq!(error(client.call("exportStart", &json!({ "format": "csv", "masterPassword": "no", "secretKey": server.secret_key, "now": 1 }).to_string())), "wrong_password");
    let started = ok(client.call("exportStart", &password(json!({ "format": "csv" }))));
    assert_eq!((started["items"].as_u64(), started["files"].as_array().unwrap().len()), (Some(1), 0));
    let csv = client.export_finish().unwrap();
    assert!(String::from_utf8_lossy(&csv).contains("Bank"));

    // A zip with the file; imported again into the vault.
    let started = ok(client.call("exportStart", &password(json!({ "format": "zip" }))));
    assert_eq!(started["files"][0]["objects"], json!([format!("{VAULT}/{file_id}/0")]));
    assert_eq!(client.export_chunk(&file_id, 0, &raw[1..]).unwrap_err().key, "attachment_damaged");
    client.export_chunk(&file_id, 0, &raw).unwrap();
    let zip = client.export_finish().unwrap();
    // Into the same account, the item is found again: nothing new.
    let summary = ok(client.import_parse(&json!({ "format": "keyless_export", "name": "x" }).to_string(), zip.clone(), None));
    assert_eq!((summary["new_items"].as_u64(), summary["same_items"].as_u64(), summary["vault_new"].clone()), (Some(0), Some(1), json!([0])));
    ok(client.call("importCancel", ""));
    // Once it is in Recently Deleted, it comes back as a new item.
    let sealed = ok(client.call("setFlags", &json!({ "id": "i1", "trashed": true, "now": 250 }).to_string()));
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [stored(&sealed, 3, 7)] }).to_string()));
    let summary = ok(client.import_parse(&json!({ "format": "keyless_export", "name": "x" }).to_string(), zip, None));
    assert_eq!(summary["new_items"], 1);
    assert_eq!((summary["total_items"].as_u64(), summary["files"].as_u64()), (Some(1), Some(1)));
    assert_eq!(error(client.call("importFiles", &json!({ "targets": [], "now": 300 }).to_string())), "invalid_request");
    let files = ok(client.call("importFiles", &json!({ "targets": [VAULT], "now": 300 }).to_string()));
    let new_id = files[0]["id"].as_str().unwrap().to_string();
    let mut chunks = Vec::new();
    client.import_file_source(&new_id).unwrap().read(|index, sealed| {
        chunks.push((index, sealed));
        true
    }).unwrap();
    assert_eq!(chunks.len(), 1);
    let committed = ok(client.call("importCommit", &json!({ "targets": [VAULT], "uploaded": [new_id], "now": 300 }).to_string()));
    assert_eq!((committed["files"].as_u64(), committed["filesFailed"].as_u64()), (Some(1), Some(0)));
    let item = &committed["items"][0];
    assert!(item["baseRevision"].is_null());
    let item_id = item["id"].as_str().unwrap().to_string();
    assert_ne!(item_id, "i1");
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [stored(item, 1, 8)] }).to_string()));
    assert_eq!(*client.attachment_open(&item_id, &new_id, 0, &chunks[0].1).unwrap(), b"hello".to_vec());
    let imported = ok(client.call("item", &json!({ "id": item_id }).to_string()));
    assert_eq!(imported["overview"]["title"], "Bank");
    assert_eq!(imported["details"]["fields"][1]["value"], "pw");
    assert_eq!(error(client.call("importCommit", &json!({ "targets": [VAULT], "now": 300 }).to_string())), "import_no_file");
    let sealed = ok(client.call("setFlags", &json!({ "id": "i1", "trashed": false, "now": 350 }).to_string()));
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [stored(&sealed, 4, 9)] }).to_string()));

    // An encrypted backup, which needs a strong password.
    assert_eq!(error(client.call("exportStart", &password(json!({ "format": "backup", "password": "password1234" })))), "backup_password_weak");
    let backup_password = "ochre lantern fjord 93 tumble quill";
    let started = ok(client.call("exportStart", &password(json!({ "format": "backup", "password": backup_password }))));
    assert_eq!(started["files"].as_array().unwrap().len(), 2);
    ok(client.call("exportFileFailed", &json!({ "id": file_id }).to_string()));
    client.export_chunk(&new_id, 0, &chunks[0].1).unwrap();
    let backup = client.export_finish().unwrap();
    assert_eq!(error(client.import_parse(&json!({ "format": "keyless_backup", "password": "wrong", "name": "x" }).to_string(), backup.clone(), None)), "backup_wrong_password");
    let summary = ok(client.import_parse(&json!({ "format": "keyless_backup", "password": backup_password, "name": "x" }).to_string(), backup, None));
    // Two items now; the file that failed is not in the backup.
    assert_eq!((summary["total_items"].as_u64(), summary["files"].as_u64()), (Some(2), Some(1)));
    ok(client.call("importCancel", ""));

    // The CSV goes back in too, into a vault made for it.
    let summary = ok(client.import_parse(&json!({ "format": "csv", "name": "Imported" }).to_string(), csv, None));
    assert_eq!(summary["total_items"], 1);
    assert_eq!(error(client.import_parse(&json!({ "format": "json", "name": "x" }).to_string(), Zeroizing::new(b"{}".to_vec()), None)), "import_unknown_json");
    let vault = ok(client.call("vaultNew", &json!({ "name": " Imported " }).to_string()));
    assert_eq!(vault["p_id"].as_str().unwrap().len(), 36);
    assert!(vault["p_enc_meta"].is_string() && vault["p_enc_vault_key"].is_string());
    assert_eq!(error(client.call("vaultNew", &json!({ "name": " " }).to_string())), "vault_name_required");
}

#[test]
fn imports_again_only_new_and_changed_items() {
    const A: &str = "33333333-3333-4333-8333-333333333333";
    const B: &str = "44444444-4444-4444-8444-444444444444";
    let server = server();
    let mut client = signed_in(&server);
    let items = json!([row(&server, A, 5, 1, &login("GitHub", "https://github.com", "pw1", 1)), row(&server, B, 6, 1, &login("Bank", "https://bank.example", "pw2", 1))]);
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": items }).to_string()));
    // GitHub as it is (its code, only in Keyless, does not count), Bank with
    // a new password, and a new login.
    let csv = "title,url,username,password\nGitHub,https://github.com,me,pw1\nBank,https://bank.example,me,pw-new\nShop,https://shop.example,me,shop\n";
    let summary = ok(client.import_parse(&json!({ "format": "csv", "name": "Imported" }).to_string(), Zeroizing::new(csv.as_bytes().to_vec()), None));
    assert_eq!(
        (summary["new_items"].as_u64(), summary["same_items"].as_u64(), summary["changed_items"].as_u64(), summary["kept_items"].as_u64()),
        (Some(1), Some(1), Some(1), Some(0))
    );
    assert_eq!(summary["vault_new"], json!([1]));
    // Shop goes where GitHub and Bank are, by default.
    assert_eq!(summary["vault_home"], json!([VAULT]));
    let committed = ok(client.call("importCommit", &json!({ "targets": [VAULT], "now": 500 }).to_string()));
    assert_eq!(committed["items"].as_array().unwrap().len(), 1);
    assert_eq!(committed["items"][0]["baseRevision"], Value::Null);
    let update = &committed["updates"][0];
    assert_eq!((update["id"].as_str(), update["baseRevision"].as_i64()), (Some(B), Some(1)));
    ok(client.call("applyItems", &json!({ "vaultId": VAULT, "items": [stored(update, 2, 7)] }).to_string()));
    let bank = ok(client.call("item", &json!({ "id": B }).to_string()));
    let fields = bank["details"]["fields"].as_array().unwrap();
    assert_eq!(fields.iter().map(|f| f["id"].as_str().unwrap()).collect::<Vec<_>>(), vec!["u", "p", "t"]);
    assert_eq!(fields[1]["value"], "pw-new");
    assert_eq!(bank["details"]["password_history"][0]["value"], "pw2");

    // Without updating, only the new one goes.
    ok(client.import_parse(&json!({ "format": "csv", "name": "Imported" }).to_string(), Zeroizing::new(csv.replace("pw-new", "pw-3").into_bytes()), None));
    let committed = ok(client.call("importCommit", &json!({ "targets": [VAULT], "now": 600, "updateChanged": false }).to_string()));
    assert_eq!((committed["items"].as_array().unwrap().len(), committed["updates"].as_array().unwrap().len()), (1, 0));
}

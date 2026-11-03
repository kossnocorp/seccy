use base64::{Engine, engine::general_purpose::STANDARD};
use seccy_core::{agent::string, payload::Payload};

const SAMPLE: &str = "AAAAIG8+9ZzWxKLkGSmnsIaywYZcvE9Nh993JhgA4OoabU/YMgAAAANnaXQAAAAOc3NoLWNvbm5lY3Rpb24AAAAjcHVibGlja2V5LWhvc3Rib3VuZC12MDBAb3BlbnNzaC5jb20BAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC88x5d8PbQ/ZBZ1zWPzOtRo8mODqAzG5BSazvWuYhaGmuVEuJzDz1tTJzCEp9So576K0Er4PJPbNHOREr+jD/UAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
const USER_KEY: &str = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC88x5d8PbQ/ZBZ1zWPzOtRo8mODqAzG5BSazvWuYhaGmuVEuJzDz1tTJzCEp9So576K0Er4PJPbNHOREr+jD/U=";
const HOST_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

#[test]
fn decodes_real_hostbound_authentication_and_matches_known_hosts() {
    let mut payload = Payload::decode(
        &STANDARD.decode(SAMPLE).unwrap(),
        &STANDARD.decode(USER_KEY).unwrap(),
    );
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("known_hosts");
    std::fs::write(&file, format!("# comment\nexample.com,192.0.2.1 ssh-ed25519 {HOST_KEY}\n[example.com]:2222 ssh-ed25519 {HOST_KEY}\n|1|hashed-salt|hashed-name ssh-ed25519 {HOST_KEY}\n@cert-authority *.example.com ssh-ed25519 {HOST_KEY}\n@revoked old.example.com ssh-ed25519 {HOST_KEY}\nwrong.example.com ssh-ed25519 AAAA\nmalformed\n")).unwrap();
    payload.enrich(&[file.clone(), dir.path().join("missing")]);
    let Payload::SshAuthentication {
        username,
        service,
        method,
        algorithm,
        host: Some(host),
        ..
    } = &payload
    else {
        panic!("wrong payload");
    };
    assert_eq!(username, "git");
    assert_eq!(service, "ssh-connection");
    assert_eq!(method, "publickey-hostbound-v00@openssh.com");
    assert_eq!(algorithm, "ecdsa-sha2-nistp256");
    assert_eq!(
        host.fingerprint,
        "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"
    );
    assert_eq!(host.known_hosts.len(), 4);
    assert_eq!(
        host.known_hosts[0].names.as_deref(),
        Some("example.com,192.0.2.1")
    );
    assert_eq!(host.known_hosts[0].file, file);
    assert_eq!(host.known_hosts[0].line, 2);
    assert!(host.known_hosts[2].hashed);
    assert!(host.known_hosts[2].names.is_none());
    assert!(host.known_hosts[3].revoked);
    assert!(payload.description().contains("not a verified destination"));
    assert!(payload.description().contains("[REVOKED]"));
}

#[test]
fn malformed_unknown_and_mismatched_requests_are_not_misclassified() {
    let bytes = STANDARD.decode(SAMPLE).unwrap();
    let key = STANDARD.decode(USER_KEY).unwrap();
    for end in 0..bytes.len() {
        assert!(matches!(
            Payload::decode(&bytes[..end], &key),
            Payload::Unknown
        ));
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(Payload::decode(&trailing, &key), Payload::Unknown));
    assert!(matches!(
        Payload::decode(&bytes, b"another key"),
        Payload::Unknown
    ));
    assert!(matches!(
        Payload::decode(&[255; 16], &key),
        Payload::Unknown
    ));
}

#[test]
fn plain_authentication_and_git_signature_have_distinct_descriptions() {
    let key = STANDARD.decode(USER_KEY).unwrap();
    let mut auth = Vec::new();
    string(&mut auth, &[1; 32]);
    auth.push(50);
    string(&mut auth, b"git\nspoofed text");
    string(&mut auth, b"ssh-connection");
    string(&mut auth, b"publickey");
    auth.push(1);
    string(&mut auth, b"ecdsa-sha2-nistp256");
    string(&mut auth, &key);
    let decoded = Payload::decode(&auth, &key);
    assert!(matches!(
        decoded,
        Payload::SshAuthentication { host: None, .. }
    ));
    assert!(decoded.description().contains("destination unknown"));
    assert!(decoded.description().contains("git\\nspoofed text"));

    let mut signing = b"SSHSIG".to_vec();
    string(&mut signing, b"git");
    string(&mut signing, b"");
    string(&mut signing, b"sha512");
    string(&mut signing, &[2; 64]);
    let decoded = Payload::decode(&signing, &key);
    assert!(matches!(decoded, Payload::SshSignature { ref namespace, .. } if namespace == "git"));
    assert!(decoded.description().contains("namespace \"git\""));
    signing.pop();
    assert!(matches!(Payload::decode(&signing, &key), Payload::Unknown));
}

#[test]
fn unavailable_or_oversized_known_hosts_does_not_block_decoding() {
    let mut payload = Payload::decode(
        &STANDARD.decode(SAMPLE).unwrap(),
        &STANDARD.decode(USER_KEY).unwrap(),
    );
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("huge");
    std::fs::File::create(&file)
        .unwrap()
        .set_len(4 * 1024 * 1024 + 1)
        .unwrap();
    payload.enrich(&[dir.path().into(), file]);
    let Payload::SshAuthentication {
        host: Some(host), ..
    } = payload
    else {
        panic!("wrong payload");
    };
    assert_eq!(host.lookup_notes.len(), 2);
    assert!(host.known_hosts.is_empty());
}

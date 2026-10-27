//! Local stand-ins for an RFC 3161 TSA and a Sigstore Rekor log, for tests
//! (`testkit` cargo feature, off by default; never in a release binary's
//! code path).
//!
//! The recorded fixtures under `cloakpipe-verify/tests/fixtures/anchoring`
//! hold real answers for two fixed batch heads. Ledger epochs are new bytes
//! every time, so tests that anchor them need an authority that answers for
//! anything. These do, with a throwaway key made at start-up, and their
//! answers pass the same offline checks real ones do:
//!
//! - [`MockTsa`] answers a `TimeStampReq` with a CMS-signed `TSTInfo`
//!   (ECDSA P-256) under a self-signed certificate with a critical
//!   `timeStamping` extended key usage, which [`MockTsa::root_pem`] gives
//!   the verifier as its pinned root.
//! - [`MockRekor`] keeps an RFC 6962 Merkle log of `hashedrekord` bodies
//!   and answers with a signed entry timestamp, an inclusion proof and a
//!   signed checkpoint, under the P-256 key [`MockRekor::key_pem`] gives.
//!
//! Each can be told to fail (HTTP 503) or to run its clock off by some
//! seconds (for back-dating tests).

use base64::Engine;
use der::asn1::{Any, BitString, GeneralizedTime, ObjectIdentifier, OctetString, SetOfVec, UtcTime};
use der::{Decode, Encode};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_EKU: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const OID_KP_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
const OID_CT_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const OID_ATTR_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const OID_ATTR_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const OID_TSA_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1");

/// SubjectPublicKeyInfo prefix of an uncompressed P-256 point.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

fn p256_spki(key: &SigningKey) -> Vec<u8> {
    let mut der = P256_SPKI_PREFIX.to_vec();
    der.extend_from_slice(key.verifying_key().to_encoded_point(false).as_bytes());
    der
}

fn pem(label: &str, der: &[u8]) -> Vec<u8> {
    let b64 = B64.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out.into_bytes()
}

/// DER TLV with a one-byte tag.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|&b| b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

/// A DER INTEGER for a non-negative big-endian magnitude.
fn der_uint(magnitude: &[u8]) -> Vec<u8> {
    let m: Vec<u8> = magnitude.iter().copied().skip_while(|&b| b == 0).collect();
    let mut content = Vec::new();
    if m.is_empty() || m[0] & 0x80 != 0 {
        content.push(0);
    }
    content.extend(m);
    tlv(0x02, &content)
}

/// What an HTTP handler sees and answers.
type Handler = Box<dyn Fn(&str, &[u8]) -> (u16, &'static str, Vec<u8>) + Send + Sync>;

/// Serve `handler` on a local port until the process exits; the base URL.
fn serve(handler: Handler) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a local port");
    let url = format!("http://{}", listener.local_addr().expect("a local address"));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
            let Ok(clone) = stream.try_clone() else { continue };
            let mut reader = BufReader::new(clone);
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            let path = line.split_whitespace().nth(1).unwrap_or_default().to_string();
            let mut len = 0usize;
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).unwrap_or(0) == 0 || h.trim_end().is_empty() {
                    break;
                }
                if let Some((k, v)) = h.split_once(':') {
                    if k.eq_ignore_ascii_case("content-length") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
            }
            let mut body = vec![0; len];
            if reader.read_exact(&mut body).is_err() {
                continue;
            }
            let (status, ctype, reply) = handler(&path, &body);
            let mut out = stream;
            let _ = out.write_all(
                format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.len()
                )
                .as_bytes(),
            );
            let _ = out.write_all(&reply);
        }
    });
    url
}

/// Behaviour shared by both mocks.
#[derive(Default)]
struct Knobs {
    failing: AtomicBool,
    clock_offset: AtomicI64,
    requests: AtomicUsize,
    answered: AtomicUsize,
}

impl Knobs {
    fn now(&self) -> i64 {
        now_unix() + self.clock_offset.load(Ordering::SeqCst)
    }
}

// ── TSA ────────────────────────────────────────────────────────────────

struct Tsa {
    key: SigningKey,
    cert: x509_cert::Certificate,
    serial: AtomicUsize,
    knobs: Knobs,
}

/// A local RFC 3161 timestamp authority.
#[derive(Clone)]
pub struct MockTsa {
    url: String,
    inner: Arc<Tsa>,
}

impl MockTsa {
    pub fn start() -> Self {
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let cert = self_signed_tsa_cert(&key);
        let inner = Arc::new(Tsa { key, cert, serial: AtomicUsize::new(1), knobs: Knobs::default() });
        let handler_state = inner.clone();
        let url = serve(Box::new(move |_path, body| handler_state.answer(body)));
        Self { url: format!("{url}/tsr"), inner }
    }

    /// Where to send `TimeStampReq`s.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The TSA certificate (PEM), to pin as the trusted root.
    pub fn root_pem(&self) -> Vec<u8> {
        pem("CERTIFICATE", &self.inner.cert.to_der().expect("a certificate encodes"))
    }

    /// Answer HTTP 503 while set.
    pub fn set_failing(&self, failing: bool) {
        self.inner.knobs.failing.store(failing, Ordering::SeqCst);
    }

    /// Stamp times this many seconds off the real clock.
    pub fn set_clock_offset(&self, secs: i64) {
        self.inner.knobs.clock_offset.store(secs, Ordering::SeqCst);
    }

    /// Requests received.
    pub fn requests(&self) -> usize {
        self.inner.knobs.requests.load(Ordering::SeqCst)
    }

    /// Timestamps issued.
    pub fn issued(&self) -> usize {
        self.inner.knobs.answered.load(Ordering::SeqCst)
    }
}

fn self_signed_tsa_cert(key: &SigningKey) -> x509_cert::Certificate {
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    let name = x509_cert::name::Name::from_str("CN=CloakPipe test TSA,O=CloakPipe tests").expect("a valid name");
    let alg = spki::AlgorithmIdentifierOwned { oid: OID_ECDSA_SHA256, parameters: None };
    let now = now_unix().max(0) as u64;
    let validity = x509_cert::time::Validity {
        not_before: x509_cert::time::Time::UtcTime(
            UtcTime::from_unix_duration(Duration::from_secs(now - 2 * 86_400)).expect("a UTC time"),
        ),
        not_after: x509_cert::time::Time::GeneralTime(
            GeneralizedTime::from_unix_duration(Duration::from_secs(now + 10 * 365 * 86_400)).expect("a time"),
        ),
    };
    let eku = ExtendedKeyUsage(vec![OID_KP_TIME_STAMPING]).to_der().expect("EKU encodes");
    let tbs = x509_cert::TbsCertificate {
        version: x509_cert::Version::V3,
        serial_number: x509_cert::serial_number::SerialNumber::new(&[0x01, 0x42]).expect("a serial"),
        signature: alg.clone(),
        issuer: name.clone(),
        validity,
        subject: name,
        subject_public_key_info: spki::SubjectPublicKeyInfoOwned::from_der(&p256_spki(key)).expect("an SPKI"),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(vec![x509_cert::ext::Extension {
            extn_id: OID_EKU,
            critical: true,
            extn_value: OctetString::new(eku).expect("an octet string"),
        }]),
    };
    let sig: Signature = key.sign(&tbs.to_der().expect("TBS encodes"));
    x509_cert::Certificate {
        tbs_certificate: tbs,
        signature_algorithm: alg,
        signature: BitString::from_bytes(sig.to_der().as_bytes()).expect("a bit string"),
    }
}

/// `TimeStampReq ::= SEQUENCE { version, messageImprint SEQUENCE { alg,
/// OCTET STRING }, reqPolicy OID OPTIONAL, nonce INTEGER OPTIONAL, ... }`:
/// the imprint and nonce.
fn parse_request(req: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    use der::{Reader, SliceReader, Tag};
    let mut r = SliceReader::new(req).ok()?;
    r.sequence(|r| {
        let _version: u8 = r.decode()?;
        let imprint = r.sequence(|m| {
            let _alg: spki::AlgorithmIdentifierOwned = m.decode()?;
            let h: OctetString = m.decode()?;
            Ok(h.as_bytes().to_vec())
        })?;
        let mut nonce = Vec::new();
        while !r.is_finished() {
            if r.peek_tag()? == Tag::Integer {
                let n: der::asn1::UintRef<'_> = r.decode()?;
                nonce = n.as_bytes().to_vec();
            } else {
                let _: der::asn1::AnyRef<'_> = r.decode()?;
            }
        }
        Ok((imprint, nonce))
    })
    .ok()
}

impl Tsa {
    fn answer(&self, body: &[u8]) -> (u16, &'static str, Vec<u8>) {
        self.knobs.requests.fetch_add(1, Ordering::SeqCst);
        if self.knobs.failing.load(Ordering::SeqCst) {
            return (503, "text/plain", b"mock TSA unavailable".to_vec());
        }
        let Some((imprint, nonce)) = parse_request(body) else {
            return (400, "text/plain", b"bad TimeStampReq".to_vec());
        };
        let tsr = self.response(&imprint, &nonce).expect("a response encodes");
        self.knobs.answered.fetch_add(1, Ordering::SeqCst);
        (200, "application/timestamp-reply", tsr)
    }

    fn response(&self, imprint: &[u8], nonce: &[u8]) -> der::Result<Vec<u8>> {
        use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
        use cms::content_info::{CmsVersion, ContentInfo};
        use cms::signed_data::{
            CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
        };
        let serial = self.serial.fetch_add(1, Ordering::SeqCst) as u64;
        let gen_time = chrono::DateTime::from_timestamp(self.knobs.now(), 0).expect("a time");
        let mut tst = Vec::new();
        tst.extend(der_uint(&[1]));
        tst.extend(OID_TSA_POLICY.to_der()?);
        let alg = tlv(0x30, &[OID_SHA256.to_der()?, vec![0x05, 0x00]].concat());
        tst.extend(tlv(0x30, &[alg, tlv(0x04, imprint)].concat()));
        tst.extend(der_uint(&serial.to_be_bytes()));
        tst.extend(tlv(0x18, gen_time.format("%Y%m%d%H%M%SZ").to_string().as_bytes()));
        if !nonce.is_empty() {
            tst.extend(der_uint(nonce));
        }
        let tst = tlv(0x30, &tst);

        let attr = |oid, value: Any| -> der::Result<x509_cert::attr::Attribute> {
            Ok(x509_cert::attr::Attribute { oid, values: SetOfVec::try_from(vec![value])? })
        };
        let digest = OctetString::new(Sha256::digest(&tst).to_vec())?;
        let signed_attrs: SetOfVec<x509_cert::attr::Attribute> = SetOfVec::try_from(vec![
            attr(OID_ATTR_CONTENT_TYPE, Any::encode_from(&OID_CT_TST_INFO)?)?,
            attr(OID_ATTR_MESSAGE_DIGEST, Any::encode_from(&digest)?)?,
        ])?;
        let sig: Signature = self.key.sign(&signed_attrs.to_der()?);
        let sha256 = spki::AlgorithmIdentifierOwned { oid: OID_SHA256, parameters: None };
        let signer = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: self.cert.tbs_certificate.issuer.clone(),
                serial_number: self.cert.tbs_certificate.serial_number.clone(),
            }),
            digest_alg: sha256.clone(),
            signed_attrs: Some(signed_attrs),
            signature_algorithm: spki::AlgorithmIdentifierOwned { oid: OID_ECDSA_SHA256, parameters: None },
            signature: OctetString::new(sig.to_der().as_bytes().to_vec())?,
            unsigned_attrs: None,
        };
        let sd = SignedData {
            version: CmsVersion::V3,
            digest_algorithms: SetOfVec::try_from(vec![sha256])?,
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: OID_CT_TST_INFO,
                econtent: Some(Any::encode_from(&OctetString::new(tst)?)?),
            },
            certificates: Some(CertificateSet(SetOfVec::try_from(vec![CertificateChoices::Certificate(
                self.cert.clone(),
            )])?)),
            crls: None,
            signer_infos: SignerInfos(SetOfVec::try_from(vec![signer])?),
        };
        let token = ContentInfo { content_type: OID_SIGNED_DATA, content: Any::encode_from(&sd)? };
        let status = tlv(0x30, &der_uint(&[0]));
        Ok(tlv(0x30, &[status, token.to_der()?].concat()))
    }
}

// ── Rekor ──────────────────────────────────────────────────────────────

struct Log {
    key: SigningKey,
    log_id: [u8; 32],
    leaves: Mutex<Vec<[u8; 32]>>,
    knobs: Knobs,
}

/// A local Rekor (v1 API) transparency log.
#[derive(Clone)]
pub struct MockRekor {
    url: String,
    inner: Arc<Log>,
}

impl MockRekor {
    pub fn start() -> Self {
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let log_id = Sha256::digest(p256_spki(&key)).into();
        let inner = Arc::new(Log { key, log_id, leaves: Mutex::new(Vec::new()), knobs: Knobs::default() });
        let handler_state = inner.clone();
        let url = serve(Box::new(move |path, body| handler_state.answer(path, body)));
        Self { url, inner }
    }

    /// The log's base URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The log's public key (PEM), the verifier's trust input.
    pub fn key_pem(&self) -> Vec<u8> {
        pem("PUBLIC KEY", &p256_spki(&self.inner.key))
    }

    /// Answer HTTP 503 while set.
    pub fn set_failing(&self, failing: bool) {
        self.inner.knobs.failing.store(failing, Ordering::SeqCst);
    }

    /// Integrate entries at this many seconds off the real clock.
    pub fn set_clock_offset(&self, secs: i64) {
        self.inner.knobs.clock_offset.store(secs, Ordering::SeqCst);
    }

    /// Requests received.
    pub fn requests(&self) -> usize {
        self.inner.knobs.requests.load(Ordering::SeqCst)
    }

    /// Entries in the log.
    pub fn entries(&self) -> usize {
        self.inner.leaves.lock().expect("log lock").len()
    }
}

fn leaf_hash(entry: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(entry);
    h.finalize().into()
}

fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// RFC 6962 Merkle tree hash.
fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let k = leaves.len().next_power_of_two() / 2;
    node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
}

/// RFC 6962 audit path of leaf `i`.
fn audit_path(leaves: &[[u8; 32]], i: usize) -> Vec<[u8; 32]> {
    if leaves.len() == 1 {
        return vec![];
    }
    let k = leaves.len().next_power_of_two() / 2;
    if i < k {
        let mut p = audit_path(&leaves[..k], i);
        p.push(mth(&leaves[k..]));
        p
    } else {
        let mut p = audit_path(&leaves[k..], i - k);
        p.push(mth(&leaves[..k]));
        p
    }
}

impl Log {
    fn answer(&self, path: &str, body: &[u8]) -> (u16, &'static str, Vec<u8>) {
        self.knobs.requests.fetch_add(1, Ordering::SeqCst);
        if self.knobs.failing.load(Ordering::SeqCst) {
            return (503, "text/plain", b"mock Rekor unavailable".to_vec());
        }
        if path != "/api/v1/log/entries" {
            return (404, "text/plain", b"not found".to_vec());
        }
        if serde_json::from_slice::<serde_json::Value>(body).is_err() {
            return (400, "text/plain", b"not JSON".to_vec());
        }
        let (index, leaves) = {
            let mut leaves = self.leaves.lock().expect("log lock");
            leaves.push(leaf_hash(body));
            (leaves.len() - 1, leaves.clone())
        };
        self.knobs.answered.fetch_add(1, Ordering::SeqCst);
        let root = mth(&leaves);
        let integrated = self.knobs.now();
        let log_id = hex::encode(self.log_id);
        let body_b64 = B64.encode(body);
        let canonical = format!(
            r#"{{"body":"{body_b64}","integratedTime":{integrated},"logID":"{log_id}","logIndex":{index}}}"#
        );
        let set: Signature = self.key.sign(canonical.as_bytes());
        let text = format!("mock-rekor - 1193050959916656506\n{}\n{}\n", leaves.len(), B64.encode(root));
        let note_sig: Signature = self.key.sign(text.as_bytes());
        let mut hint = self.log_id[..4].to_vec();
        hint.extend_from_slice(note_sig.to_der().as_bytes());
        let checkpoint = format!("{text}\n\u{2014} mock-rekor {}\n", B64.encode(hint));
        let uuid = format!("108e9186e8c5677a{}", hex::encode(leaf_hash(body)));
        let entry = serde_json::json!({
            uuid: {
                "body": body_b64,
                "integratedTime": integrated,
                "logID": log_id,
                "logIndex": index,
                "verification": {
                    "signedEntryTimestamp": B64.encode(set.to_der().as_bytes()),
                    "inclusionProof": {
                        "checkpoint": checkpoint,
                        "hashes": audit_path(&leaves, index).iter().map(hex::encode).collect::<Vec<_>>(),
                        "logIndex": index,
                        "rootHash": hex::encode(root),
                        "treeSize": leaves.len(),
                    },
                },
            }
        });
        (201, "application/json", entry.to_string().into_bytes())
    }
}

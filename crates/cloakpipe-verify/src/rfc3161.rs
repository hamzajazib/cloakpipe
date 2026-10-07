//! RFC 3161 timestamp verification, fully offline.
//!
//! Input is the complete DER `TimeStampResp` a TSA returned, the SHA-256
//! the caller asked to be stamped, the request nonce and the roots the
//! caller trusts. Every check below must pass; anything that cannot be
//! parsed or is not understood is rejected.
//!
//! 1. `status` is granted (0) or grantedWithMods (1) and a token is present.
//! 2. The token is CMS `SignedData` over `id-ct-TSTInfo`, with exactly one
//!    `SignerInfo` that carries signed attributes.
//! 3. Signed attributes: `contentType` is `id-ct-TSTInfo`; `messageDigest`
//!    equals the digest of the encapsulated TSTInfo; an ESS
//!    `signingCertificate` / `signingCertificateV2`, if present, names the
//!    signer certificate by hash (and, if given, by issuer name and serial).
//! 4. The signature over the DER signed attributes verifies under the
//!    signer certificate's key: RSA PKCS#1 v1.5 (2048 bits or more) or
//!    ECDSA P-256 / P-384, with SHA-256/384/512.
//! 5. TSTInfo: version 1, message imprint is SHA-256 and equals the
//!    caller's hash, nonce equals the request nonce.
//! 6. The signer certificate has a critical extended key usage of exactly
//!    `id-kp-timeStamping` and chains, through certificates carried in the
//!    token, to one of the caller's roots. Every certificate on the path,
//!    the root included, is valid at `genTime`; every issuer, the root
//!    included, is a CA within its path length that may sign certificates
//!    and, if it restricts its extended key usage, allows timeStamping; no
//!    certificate on the path, the root included, carries a critical
//!    extension this verifier does not understand. A root that is itself
//!    the signer certificate (a pinned TSA certificate) is trusted as is.

use crate::time::{parse_generalized_time, rfc3339_from_unix};
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use der::asn1::{AnyRef, ObjectIdentifier, OctetString, OctetStringRef, UintRef};
use der::{Decode, Encode, Reader, SliceReader, Tag, TagNumber, Tagged};
use sha2::Digest;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use thiserror::Error;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
use x509_cert::Certificate;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Rfc3161Error {
    #[error("malformed timestamp response: {0}")]
    Malformed(String),
    #[error("TSA did not grant the request (PKIStatus {0})")]
    NotGranted(u32),
    #[error("unsupported algorithm: {0}")]
    Unsupported(String),
    #[error("signed attributes invalid: {0}")]
    SignedAttrs(String),
    #[error("TSA signature does not verify")]
    SignatureInvalid,
    #[error("ESS signing-certificate does not name the signer certificate")]
    SigningCertMismatch,
    #[error("message imprint does not match the anchored hash")]
    ImprintMismatch,
    #[error("nonce missing or different from the request nonce")]
    NonceMismatch,
    #[error("TSA certificate not usable for timestamping: {0}")]
    BadSignerCert(String),
    #[error("certificate chain does not reach a trusted root: {0}")]
    UntrustedChain(String),
    #[error("trusted roots: {0}")]
    BadTrustInput(String),
}

type Result<T> = std::result::Result<T, Rfc3161Error>;

fn malformed(e: impl std::fmt::Display) -> Rfc3161Error {
    Rfc3161Error::Malformed(e.to_string())
}

const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const OID_CT_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const OID_ATTR_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const OID_ATTR_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const OID_ATTR_SIGNING_CERT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");
const OID_ATTR_SIGNING_CERT_V2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
const OID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_SHA384_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_SHA512_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_KP_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
const OID_ANY_EKU: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37.0");
const OID_EXT_SKI: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const OID_EXT_SAN: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
const OID_EXT_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_EXT_CERT_POLICIES: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.32");
const OID_EXT_AKI: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");
const OID_EXT_EKU: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

/// Extensions whose semantics this verifier enforces or that cannot
/// restrict a path; any other extension marked critical rejects the path.
const UNDERSTOOD_EXTENSIONS: [ObjectIdentifier; 7] = [
    OID_EXT_SKI,
    OID_EXT_KEY_USAGE,
    OID_EXT_SAN,
    OID_EXT_BASIC_CONSTRAINTS,
    OID_EXT_CERT_POLICIES,
    OID_EXT_AKI,
    OID_EXT_EKU,
];

/// Longest certificate path accepted (signer + intermediates).
const MAX_PATH: usize = 6;
const MIN_RSA_BITS: usize = 2048;

/// The certificates a TSA must chain to, supplied by the verifying party.
#[derive(Debug, Clone)]
pub struct TrustedRoots {
    certs: Vec<Certificate>,
    ders: Vec<Vec<u8>>,
}

impl TrustedRoots {
    /// Parse one or more PEM `CERTIFICATE` blocks. Anything else, or no
    /// certificate at all, is an error.
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let bad = |m: String| Rfc3161Error::BadTrustInput(m);
        let text = std::str::from_utf8(pem).map_err(|_| bad("PEM is not UTF-8".into()))?;
        let (mut certs, mut ders) = (Vec::new(), Vec::new());
        let mut rest = text;
        while let Some(start) = rest.find("-----BEGIN ") {
            let block = &rest[start..];
            let end_marker = block.find("-----END ").ok_or_else(|| bad("unterminated PEM block".into()))?;
            let close = block[end_marker + 9..].find("-----").ok_or_else(|| bad("unterminated PEM block".into()))?;
            let block_end = end_marker + 9 + close + 5;
            let (label, der_bytes) =
                der::pem::decode_vec(&block.as_bytes()[..block_end]).map_err(|e| bad(format!("PEM: {e}")))?;
            if label != "CERTIFICATE" {
                return Err(bad(format!("expected CERTIFICATE, found {label}")));
            }
            let cert = Certificate::from_der(&der_bytes).map_err(|e| bad(format!("certificate: {e}")))?;
            certs.push(cert);
            ders.push(der_bytes);
            rest = &block[block_end..];
        }
        if certs.is_empty() {
            return Err(bad("no certificate in PEM".into()));
        }
        Ok(Self { certs, ders })
    }
}

/// What a verified timestamp attests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTimestamp {
    /// `genTime`, whole seconds, RFC 3339 UTC.
    pub gen_time: String,
    pub gen_time_unix: i64,
    /// TSTInfo serial number, hex.
    pub serial: String,
    /// TSA policy OID.
    pub policy: String,
    /// Subject of the TSA's signing certificate.
    pub tsa_subject: String,
}

/// Verify a DER `TimeStampResp` offline. See the module docs for the
/// checks.
pub fn verify_timestamp_response(
    tsr: &[u8],
    expected_sha256: &[u8; 32],
    expected_nonce: &[u8],
    roots: &TrustedRoots,
) -> Result<VerifiedTimestamp> {
    let token = parse_response(tsr)?;
    let sd = parse_signed_data(&token)?;
    let tst_der = encapsulated_tst_info(&sd)?;
    let signer_info = single_signer(&sd)?;
    let certs = embedded_certs(&sd)?;
    let signer = find_signer_cert(&signer_info.sid, &certs)?;
    let digest_alg = hash_alg(&signer_info.digest_alg)?;
    check_signed_attrs(signer_info, digest_alg, &tst_der, signer)?;
    verify_cms_signature(signer_info, digest_alg, signer)?;

    let tst = TstInfo::from_der(&tst_der)?;
    if hash_alg(&tst.imprint_alg)? != HashAlg::Sha256 || tst.imprint.as_slice() != expected_sha256 {
        return Err(Rfc3161Error::ImprintMismatch);
    }
    match &tst.nonce {
        Some(n) if strip_zeros(n) == strip_zeros(expected_nonce) && !strip_zeros(n).is_empty() => {}
        _ => return Err(Rfc3161Error::NonceMismatch),
    }

    check_timestamping_cert(signer)?;
    validate_path(signer, &certs, roots, tst.gen_time)?;

    Ok(VerifiedTimestamp {
        gen_time: rfc3339_from_unix(tst.gen_time),
        gen_time_unix: tst.gen_time,
        serial: hex::encode(strip_zeros(&tst.serial)),
        policy: tst.policy.to_string(),
        tsa_subject: signer.tbs_certificate.subject.to_string(),
    })
}

fn strip_zeros(b: &[u8]) -> &[u8] {
    let n = b.iter().take_while(|&&x| x == 0).count();
    &b[n..]
}

// ── Response and SignedData ─────────────────────────────────────────────

/// `TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken OPTIONAL }`
/// with `PKIStatusInfo ::= SEQUENCE { status INTEGER, statusString OPTIONAL,
/// failInfo OPTIONAL }`. Returns the token (a `ContentInfo`).
fn parse_response(tsr: &[u8]) -> Result<ContentInfo> {
    let mut r = SliceReader::new(tsr).map_err(malformed)?;
    let (status, token) = r
        .sequence(|r| {
            let status: u32 = r.sequence(|s| {
                let v: u32 = s.decode()?;
                // statusString (SEQUENCE OF UTF8String) and failInfo (BIT
                // STRING) are informational; consume them.
                while !s.is_finished() {
                    let _: AnyRef<'_> = s.decode()?;
                }
                Ok(v)
            })?;
            let token: Option<ContentInfo> = if r.is_finished() { None } else { Some(r.decode()?) };
            Ok((status, token))
        })
        .map_err(malformed)?;
    r.finish(()).map_err(malformed)?;
    if status > 1 {
        return Err(Rfc3161Error::NotGranted(status));
    }
    token.ok_or_else(|| malformed("granted response carries no token"))
}

fn parse_signed_data(token: &ContentInfo) -> Result<SignedData> {
    if token.content_type != OID_SIGNED_DATA {
        return Err(malformed(format!("token content type {} is not signedData", token.content_type)));
    }
    token.content.decode_as::<SignedData>().map_err(malformed)
}

fn encapsulated_tst_info(sd: &SignedData) -> Result<Vec<u8>> {
    let eci = &sd.encap_content_info;
    if eci.econtent_type != OID_CT_TST_INFO {
        return Err(malformed(format!("encapsulated content {} is not TSTInfo", eci.econtent_type)));
    }
    let any = eci.econtent.as_ref().ok_or_else(|| malformed("TSTInfo content is detached"))?;
    let os: OctetString = any.decode_as().map_err(malformed)?;
    Ok(os.into_bytes())
}

fn single_signer(sd: &SignedData) -> Result<&SignerInfo> {
    let infos = sd.signer_infos.0.as_slice();
    match infos {
        [one] => Ok(one),
        _ => Err(malformed(format!("expected exactly one SignerInfo, found {}", infos.len()))),
    }
}

fn embedded_certs(sd: &SignedData) -> Result<Vec<Certificate>> {
    let set = sd.certificates.as_ref().ok_or_else(|| malformed("token carries no certificates (certReq)"))?;
    let mut out = Vec::new();
    for c in set.0.iter() {
        match c {
            CertificateChoices::Certificate(c) => out.push(c.clone()),
            CertificateChoices::Other(_) => return Err(malformed("non-X.509 certificate in token")),
        }
    }
    Ok(out)
}

fn find_signer_cert<'a>(sid: &SignerIdentifier, certs: &'a [Certificate]) -> Result<&'a Certificate> {
    let found: Vec<&Certificate> = match sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => certs
            .iter()
            .filter(|c| {
                c.tbs_certificate.serial_number == ias.serial_number && same_name(&c.tbs_certificate.issuer, &ias.issuer)
            })
            .collect(),
        SignerIdentifier::SubjectKeyIdentifier(ski) => certs
            .iter()
            .filter(|c| {
                extension(c, OID_EXT_SKI)
                    .and_then(|e| OctetString::from_der(e.extn_value.as_bytes()).ok())
                    .is_some_and(|v| v == ski.0)
            })
            .collect(),
    };
    match found.as_slice() {
        [one] => Ok(one),
        [] => Err(Rfc3161Error::BadSignerCert("signer certificate not in token".into())),
        _ => Err(Rfc3161Error::BadSignerCert("signer identifier is ambiguous".into())),
    }
}

fn same_name(a: &x509_cert::name::Name, b: &x509_cert::name::Name) -> bool {
    matches!((a.to_der(), b.to_der()), (Ok(x), Ok(y)) if x == y)
}

fn extension(c: &Certificate, oid: ObjectIdentifier) -> Option<&x509_cert::ext::Extension> {
    c.tbs_certificate.extensions.as_ref()?.iter().find(|e| e.extn_id == oid)
}

// ── Signed attributes and the CMS signature ─────────────────────────────

fn attr_value(si: &SignerInfo, oid: ObjectIdentifier) -> Result<Option<&der::Any>> {
    let attrs = si.signed_attrs.as_ref().ok_or_else(|| Rfc3161Error::SignedAttrs("absent".into()))?;
    let matching: Vec<_> = attrs.iter().filter(|a| a.oid == oid).collect();
    match matching.as_slice() {
        [] => Ok(None),
        [a] => match a.values.as_slice() {
            [v] => Ok(Some(v)),
            _ => Err(Rfc3161Error::SignedAttrs(format!("{oid} must have exactly one value"))),
        },
        _ => Err(Rfc3161Error::SignedAttrs(format!("{oid} appears more than once"))),
    }
}

fn check_signed_attrs(si: &SignerInfo, digest_alg: HashAlg, tst_der: &[u8], signer: &Certificate) -> Result<()> {
    let bad = |m: &str| Rfc3161Error::SignedAttrs(m.into());
    let ct = attr_value(si, OID_ATTR_CONTENT_TYPE)?.ok_or_else(|| bad("contentType missing"))?;
    if ct.decode_as::<ObjectIdentifier>().map_err(|_| bad("contentType unreadable"))? != OID_CT_TST_INFO {
        return Err(bad("contentType is not TSTInfo"));
    }
    let md = attr_value(si, OID_ATTR_MESSAGE_DIGEST)?.ok_or_else(|| bad("messageDigest missing"))?;
    let md = md.decode_as::<OctetString>().map_err(|_| bad("messageDigest unreadable"))?;
    if md.as_bytes() != digest_alg.digest(tst_der).as_slice() {
        return Err(bad("messageDigest does not match the TSTInfo"));
    }

    let signer_der = signer.to_der().map_err(malformed)?;
    if let Some(v) = attr_value(si, OID_ATTR_SIGNING_CERT)? {
        let (hash, is) = first_ess_cert_id(&v.to_der().map_err(malformed)?, false)?;
        check_ess(HashAlg::Sha1, &hash, is.as_ref(), &signer_der, signer)?;
    }
    if let Some(v) = attr_value(si, OID_ATTR_SIGNING_CERT_V2)? {
        let (alg, hash, is) = first_ess_cert_id_v2(&v.to_der().map_err(malformed)?)?;
        check_ess(alg, &hash, is.as_ref(), &signer_der, signer)?;
    }
    Ok(())
}

fn check_ess(
    alg: HashAlg,
    hash: &[u8],
    issuer_serial: Option<&IssuerSerial>,
    signer_der: &[u8],
    signer: &Certificate,
) -> Result<()> {
    if alg.digest(signer_der) != hash {
        return Err(Rfc3161Error::SigningCertMismatch);
    }
    if let Some(is) = issuer_serial {
        if strip_zeros(&is.serial) != strip_zeros(signer.tbs_certificate.serial_number.as_bytes()) {
            return Err(Rfc3161Error::SigningCertMismatch);
        }
        // The issuer must be named as a directory name equal to the
        // signer certificate's issuer; any other form is not understood.
        let names_issuer = is.issuer.iter().any(|g| {
            matches!(g, x509_cert::ext::pkix::name::GeneralName::DirectoryName(n)
                if same_name(n, &signer.tbs_certificate.issuer))
        });
        if !names_issuer {
            return Err(Rfc3161Error::SigningCertMismatch);
        }
    }
    Ok(())
}

/// `SigningCertificate ::= SEQUENCE { certs SEQUENCE OF ESSCertID, policies
/// OPTIONAL }`, `ESSCertID ::= SEQUENCE { certHash OCTET STRING,
/// issuerSerial IssuerSerial OPTIONAL }`. Returns the first ESSCertID, which
/// identifies the signer.
fn first_ess_cert_id(der_bytes: &[u8], _v2: bool) -> Result<(Vec<u8>, Option<IssuerSerial>)> {
    let mut r = SliceReader::new(der_bytes).map_err(malformed)?;
    let out = r
        .sequence(|r| {
            let first = r.sequence(|certs| {
                let first = certs.sequence(|id| {
                    let hash: OctetStringRef<'_> = id.decode()?;
                    let serial = issuer_serial(id)?;
                    Ok((hash.as_bytes().to_vec(), serial))
                })?;
                while !certs.is_finished() {
                    let _: AnyRef<'_> = certs.decode()?;
                }
                Ok(first)
            })?;
            while !r.is_finished() {
                let _: AnyRef<'_> = r.decode()?;
            }
            Ok(first)
        })
        .map_err(|e| Rfc3161Error::SignedAttrs(format!("signingCertificate: {e}")))?;
    r.finish(out).map_err(malformed)
}

/// `ESSCertIDv2 ::= SEQUENCE { hashAlgorithm DEFAULT sha256, certHash,
/// issuerSerial OPTIONAL }`.
fn first_ess_cert_id_v2(der_bytes: &[u8]) -> Result<(HashAlg, Vec<u8>, Option<IssuerSerial>)> {
    let mut r = SliceReader::new(der_bytes).map_err(malformed)?;
    let (alg, hash, serial) = r
        .sequence(|r| {
            let first = r.sequence(|certs| {
                let first = certs.sequence(|id| {
                    let alg: Option<AlgorithmIdentifierOwned> =
                        if id.peek_tag()? == Tag::Sequence { Some(id.decode()?) } else { None };
                    let hash: OctetStringRef<'_> = id.decode()?;
                    let serial = issuer_serial(id)?;
                    Ok((alg, hash.as_bytes().to_vec(), serial))
                })?;
                while !certs.is_finished() {
                    let _: AnyRef<'_> = certs.decode()?;
                }
                Ok(first)
            })?;
            while !r.is_finished() {
                let _: AnyRef<'_> = r.decode()?;
            }
            Ok(first)
        })
        .map_err(|e| Rfc3161Error::SignedAttrs(format!("signingCertificateV2: {e}")))?;
    r.finish(()).map_err(malformed)?;
    let alg = match alg {
        Some(a) => hash_alg(&a)?,
        None => HashAlg::Sha256,
    };
    Ok((alg, hash, serial))
}

/// Optional trailing `IssuerSerial ::= SEQUENCE { issuer GeneralNames,
/// serialNumber INTEGER }`; returns the serial.
/// `IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber INTEGER }`.
fn issuer_serial<'a, R: Reader<'a>>(r: &mut R) -> der::Result<Option<IssuerSerial>> {
    if r.is_finished() {
        return Ok(None);
    }
    let is = r.sequence(|is| {
        let issuer: x509_cert::ext::pkix::name::GeneralNames = is.decode()?;
        let serial: der::asn1::IntRef<'_> = is.decode()?;
        Ok(IssuerSerial { issuer, serial: serial.as_bytes().to_vec() })
    })?;
    Ok(Some(is))
}

/// The signer certificate's issuer and serial, as named by an ESSCertID.
#[derive(Debug, Clone)]
struct IssuerSerial {
    issuer: x509_cert::ext::pkix::name::GeneralNames,
    serial: Vec<u8>,
}

fn verify_cms_signature(si: &SignerInfo, digest_alg: HashAlg, signer: &Certificate) -> Result<()> {
    let attrs = si.signed_attrs.as_ref().ok_or_else(|| Rfc3161Error::SignedAttrs("absent".into()))?;
    // The signature covers the DER of the attributes as a SET OF.
    let signed = attrs.to_der().map_err(malformed)?;
    verify_signature(
        &signer.tbs_certificate.subject_public_key_info,
        &si.signature_algorithm,
        Some(digest_alg),
        &signed,
        si.signature.as_bytes(),
    )
}

// ── Algorithms ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha1 => sha1::Sha1::digest(data).to_vec(),
            HashAlg::Sha256 => sha2::Sha256::digest(data).to_vec(),
            HashAlg::Sha384 => sha2::Sha384::digest(data).to_vec(),
            HashAlg::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }
}

/// A digest AlgorithmIdentifier; parameters must be absent or NULL.
fn hash_alg(a: &AlgorithmIdentifierOwned) -> Result<HashAlg> {
    if let Some(p) = &a.parameters {
        if p.tag() != Tag::Null {
            return Err(Rfc3161Error::Unsupported(format!("digest parameters for {}", a.oid)));
        }
    }
    match a.oid {
        OID_SHA1 => Ok(HashAlg::Sha1),
        OID_SHA256 => Ok(HashAlg::Sha256),
        OID_SHA384 => Ok(HashAlg::Sha384),
        OID_SHA512 => Ok(HashAlg::Sha512),
        o => Err(Rfc3161Error::Unsupported(format!("digest {o}"))),
    }
}

/// Verify `sig` over `msg` with the key in `spki`.
///
/// `cms_digest` is the SignerInfo digest algorithm: with plain
/// `rsaEncryption` it selects the hash; with a combined algorithm it must
/// agree with it.
fn verify_signature(
    spki: &SubjectPublicKeyInfoOwned,
    sig_alg: &AlgorithmIdentifierOwned,
    cms_digest: Option<HashAlg>,
    msg: &[u8],
    sig: &[u8],
) -> Result<()> {
    let unsupported = |what: String| Rfc3161Error::Unsupported(what);
    let (is_rsa, hash) = match sig_alg.oid {
        OID_RSA => (true, cms_digest.ok_or_else(|| unsupported("rsaEncryption without a digest".into()))?),
        OID_SHA256_RSA => (true, HashAlg::Sha256),
        OID_SHA384_RSA => (true, HashAlg::Sha384),
        OID_SHA512_RSA => (true, HashAlg::Sha512),
        OID_ECDSA_SHA256 => (false, HashAlg::Sha256),
        OID_ECDSA_SHA384 => (false, HashAlg::Sha384),
        OID_ECDSA_SHA512 => (false, HashAlg::Sha512),
        o => return Err(unsupported(format!("signature algorithm {o}"))),
    };
    if cms_digest.is_some_and(|d| d != hash) {
        return Err(unsupported("signature hash differs from the SignerInfo digest".into()));
    }
    if is_rsa {
        // RSA parameters are NULL or absent; ECDSA parameters are absent.
        if sig_alg.parameters.as_ref().is_some_and(|p| p.tag() != Tag::Null) {
            return Err(unsupported("RSA signature parameters".into()));
        }
    } else if sig_alg.parameters.is_some() {
        return Err(unsupported("ECDSA signature parameters".into()));
    }
    let digest = hash.digest(msg);
    let key_bits = spki.subject_public_key.as_bytes().ok_or_else(|| malformed("public key has unused bits"))?;

    match (is_rsa, spki.algorithm.oid) {
        (true, OID_RSA) => {
            use rsa::pkcs1::DecodeRsaPublicKey;
            use rsa::traits::PublicKeyParts;
            let key = rsa::RsaPublicKey::from_pkcs1_der(key_bits).map_err(|e| unsupported(format!("RSA key: {e}")))?;
            if key.size() * 8 < MIN_RSA_BITS {
                return Err(unsupported(format!("RSA key of {} bits", key.size() * 8)));
            }
            let scheme = match hash {
                HashAlg::Sha256 => rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                HashAlg::Sha384 => rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
                HashAlg::Sha512 => rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
                HashAlg::Sha1 => return Err(unsupported("SHA-1 signatures".into())),
            };
            key.verify(scheme, &digest, sig).map_err(|_| Rfc3161Error::SignatureInvalid)
        }
        (false, OID_EC_PUBLIC_KEY) => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            if hash == HashAlg::Sha1 {
                return Err(unsupported("SHA-1 signatures".into()));
            }
            let curve: ObjectIdentifier = spki
                .algorithm
                .parameters
                .as_ref()
                .ok_or_else(|| unsupported("EC key without a named curve".into()))?
                .decode_as()
                .map_err(|_| unsupported("EC key without a named curve".into()))?;
            match curve {
                OID_P256 => {
                    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bits).map_err(malformed)?;
                    let s = p256::ecdsa::Signature::from_der(sig).map_err(|_| Rfc3161Error::SignatureInvalid)?;
                    vk.verify_prehash(&digest, &s).map_err(|_| Rfc3161Error::SignatureInvalid)
                }
                OID_P384 => {
                    let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bits).map_err(malformed)?;
                    let s = p384::ecdsa::Signature::from_der(sig).map_err(|_| Rfc3161Error::SignatureInvalid)?;
                    vk.verify_prehash(&digest, &s).map_err(|_| Rfc3161Error::SignatureInvalid)
                }
                c => Err(unsupported(format!("curve {c}"))),
            }
        }
        (_, k) => Err(unsupported(format!("key type {k} for signature {}", sig_alg.oid))),
    }
}

// ── TSTInfo ─────────────────────────────────────────────────────────────

struct TstInfo {
    policy: ObjectIdentifier,
    imprint_alg: AlgorithmIdentifierOwned,
    imprint: Vec<u8>,
    serial: Vec<u8>,
    gen_time: i64,
    nonce: Option<Vec<u8>>,
}

impl TstInfo {
    /// ```text
    /// TSTInfo ::= SEQUENCE {
    ///   version INTEGER { v1(1) }, policy TSAPolicyId,
    ///   messageImprint MessageImprint, serialNumber INTEGER,
    ///   genTime GeneralizedTime, accuracy Accuracy OPTIONAL,
    ///   ordering BOOLEAN DEFAULT FALSE, nonce INTEGER OPTIONAL,
    ///   tsa [0] GeneralName OPTIONAL, extensions [1] IMPLICIT Extensions OPTIONAL }
    /// ```
    fn from_der(bytes: &[u8]) -> Result<Self> {
        let mut r = SliceReader::new(bytes).map_err(malformed)?;
        let (version, info, gen_raw) = r
            .sequence(|r| {
                let version: u8 = r.decode()?;
                let policy: ObjectIdentifier = r.decode()?;
                let (imprint_alg, imprint) = r.sequence(|m| {
                    let alg: AlgorithmIdentifierOwned = m.decode()?;
                    let h: OctetStringRef<'_> = m.decode()?;
                    Ok((alg, h.as_bytes().to_vec()))
                })?;
                let serial: der::asn1::IntRef<'_> = r.decode()?;
                let gen: AnyRef<'_> = r.decode()?;
                if gen.tag() != Tag::GeneralizedTime {
                    return Err(gen.tag().unexpected_error(Some(Tag::GeneralizedTime)));
                }
                // Optional fields, each at most once and in schema order.
                let mut nonce = None;
                let mut stage = 0u8;
                while !r.is_finished() {
                    let tag = r.peek_tag()?;
                    let next = match tag {
                        Tag::Sequence => 1,
                        Tag::Boolean => 2,
                        Tag::Integer => 3,
                        Tag::ContextSpecific { number, .. } if number == TagNumber::N0 => 4,
                        Tag::ContextSpecific { number, .. } if number == TagNumber::N1 => 5,
                        t => return Err(t.unexpected_error(None)),
                    };
                    if next <= stage {
                        return Err(tag.unexpected_error(None));
                    }
                    stage = next;
                    if next == 3 {
                        let n: UintRef<'_> = r.decode()?;
                        nonce = Some(n.as_bytes().to_vec());
                    } else {
                        let _: AnyRef<'_> = r.decode()?;
                    }
                }
                let info = TstInfo {
                    policy,
                    imprint_alg,
                    imprint,
                    serial: serial.as_bytes().to_vec(),
                    gen_time: 0,
                    nonce,
                };
                Ok((version, info, gen.value().to_vec()))
            })
            .map_err(malformed)?;
        r.finish(()).map_err(malformed)?;
        if version != 1 {
            return Err(malformed(format!("TSTInfo version {version}")));
        }
        let gen_time = parse_generalized_time(&gen_raw).ok_or_else(|| malformed("genTime is not a valid time"))?;
        Ok(TstInfo { gen_time, ..info })
    }
}

// ── Certificates ────────────────────────────────────────────────────────

fn check_timestamping_cert(signer: &Certificate) -> Result<()> {
    let bad = |m: &str| Rfc3161Error::BadSignerCert(m.into());
    let eku = extension(signer, OID_EXT_EKU).ok_or_else(|| bad("no extended key usage"))?;
    if !eku.critical {
        return Err(bad("extended key usage is not critical"));
    }
    let eku = ExtendedKeyUsage::from_der(eku.extn_value.as_bytes()).map_err(|_| bad("extended key usage unreadable"))?;
    if eku.0 != [OID_KP_TIME_STAMPING] {
        return Err(bad("extended key usage is not exactly timeStamping"));
    }
    if let Some(ku) = extension(signer, OID_EXT_KEY_USAGE) {
        let ku = KeyUsage::from_der(ku.extn_value.as_bytes()).map_err(|_| bad("key usage unreadable"))?;
        if !ku.digital_signature() && !ku.non_repudiation() {
            return Err(bad("key usage forbids signing"));
        }
    }
    Ok(())
}

fn check_validity(c: &Certificate, at: i64) -> Result<()> {
    let v = &c.tbs_certificate.validity;
    let nb = v.not_before.to_unix_duration().as_secs() as i64;
    let na = v.not_after.to_unix_duration().as_secs() as i64;
    if at < nb || at > na {
        return Err(Rfc3161Error::UntrustedChain(format!(
            "`{}` is not valid at {}",
            c.tbs_certificate.subject,
            rfc3339_from_unix(at)
        )));
    }
    Ok(())
}

fn check_critical_extensions(c: &Certificate) -> Result<()> {
    for e in c.tbs_certificate.extensions.iter().flatten() {
        if e.critical && !UNDERSTOOD_EXTENSIONS.contains(&e.extn_id) {
            return Err(Rfc3161Error::UntrustedChain(format!(
                "`{}` has unsupported critical extension {}",
                c.tbs_certificate.subject, e.extn_id
            )));
        }
    }
    Ok(())
}

/// `issuer` may sign certificates: CA basic constraints, a path length
/// that admits `below` intermediates under it, and keyCertSign if key
/// usage is present.
fn check_ca(issuer: &Certificate, below: usize) -> Result<()> {
    let fail = |m: &str| Rfc3161Error::UntrustedChain(format!("`{}` {m}", issuer.tbs_certificate.subject));
    let bc = extension(issuer, OID_EXT_BASIC_CONSTRAINTS).ok_or_else(|| fail("is not a CA"))?;
    let bc = BasicConstraints::from_der(bc.extn_value.as_bytes()).map_err(|_| fail("has unreadable constraints"))?;
    if !bc.ca {
        return Err(fail("is not a CA"));
    }
    if bc.path_len_constraint.is_some_and(|n| (n as usize) < below) {
        return Err(fail("path length exceeded"));
    }
    if let Some(ku) = extension(issuer, OID_EXT_KEY_USAGE) {
        let ku = KeyUsage::from_der(ku.extn_value.as_bytes()).map_err(|_| fail("has unreadable key usage"))?;
        if !ku.key_cert_sign() {
            return Err(fail("may not sign certificates"));
        }
    }
    Ok(())
}

/// A CA that restricts its extended key usage must allow timestamping
/// (or any purpose); one restricted to, say, code signing cannot vouch for
/// a TSA.
fn check_issuer_eku(issuer: &Certificate) -> Result<()> {
    let fail = |m: &str| Rfc3161Error::UntrustedChain(format!("`{}` {m}", issuer.tbs_certificate.subject));
    let Some(eku) = extension(issuer, OID_EXT_EKU) else { return Ok(()) };
    let eku = ExtendedKeyUsage::from_der(eku.extn_value.as_bytes()).map_err(|_| fail("has unreadable EKU"))?;
    if !eku.0.iter().any(|o| *o == OID_KP_TIME_STAMPING || *o == OID_ANY_EKU) {
        return Err(fail("is not allowed to certify timeStamping"));
    }
    Ok(())
}

fn signed_by(child: &Certificate, issuer: &Certificate) -> bool {
    if !same_name(&child.tbs_certificate.issuer, &issuer.tbs_certificate.subject) {
        return false;
    }
    let Ok(tbs) = child.tbs_certificate.to_der() else { return false };
    let Some(sig) = child.signature.as_bytes() else { return false };
    if child.signature_algorithm != child.tbs_certificate.signature {
        return false;
    }
    verify_signature(&issuer.tbs_certificate.subject_public_key_info, &child.signature_algorithm, None, &tbs, sig)
        .is_ok()
}

/// Build a path from `signer` to a trusted root using the token's
/// certificates as intermediates, checking each link at `at`.
fn validate_path(signer: &Certificate, pool: &[Certificate], roots: &TrustedRoots, at: i64) -> Result<()> {
    let mut current = signer;
    // `intermediates`: CA certificates already below the issuer we look for.
    for intermediates in 0..MAX_PATH {
        check_validity(current, at)?;
        check_critical_extensions(current)?;
        let current_der = current.to_der().map_err(malformed)?;
        if roots.ders.contains(&current_der) {
            return Ok(());
        }
        if let Some(root) = roots.certs.iter().find(|r| signed_by(current, r)) {
            // Pinning a certificate trusts its key, not its right to issue:
            // the anchor must itself be a CA that may sign this path.
            check_validity(root, at)?;
            check_critical_extensions(root)?;
            check_ca(root, intermediates)?;
            check_issuer_eku(root)?;
            return Ok(());
        }
        let next = pool
            .iter()
            .filter(|c| c.to_der().map(|d| d != current_der).unwrap_or(false))
            .find(|c| signed_by(current, c))
            .ok_or_else(|| {
                Rfc3161Error::UntrustedChain(format!("no trusted issuer for `{}`", current.tbs_certificate.issuer))
            })?;
        check_ca(next, intermediates)?;
        check_issuer_eku(next)?;
        current = next;
    }
    Err(Rfc3161Error::UntrustedChain("path too long".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::ext::pkix::name::GeneralName;

    fn freetsa_signer() -> Certificate {
        let tsr = include_bytes!("../tests/fixtures/anchoring/freetsa-honest.tsr");
        let sd = parse_signed_data(&parse_response(tsr).unwrap()).unwrap();
        let certs = embedded_certs(&sd).unwrap();
        find_signer_cert(&single_signer(&sd).unwrap().sid, &certs).unwrap().clone()
    }

    fn is(issuer: Vec<GeneralName>, c: &Certificate) -> IssuerSerial {
        IssuerSerial { issuer, serial: c.tbs_certificate.serial_number.as_bytes().to_vec() }
    }

    #[test]
    fn ess_issuer_serial_must_name_the_signers_issuer() {
        let c = freetsa_signer();
        let der = c.to_der().unwrap();
        let hash = HashAlg::Sha256.digest(&der);
        assert_ne!(c.tbs_certificate.issuer, c.tbs_certificate.subject);
        let right = is(vec![GeneralName::DirectoryName(c.tbs_certificate.issuer.clone())], &c);
        check_ess(HashAlg::Sha256, &hash, Some(&right), &der, &c).expect("matching issuer and serial");
        let wrong = is(vec![GeneralName::DirectoryName(c.tbs_certificate.subject.clone())], &c);
        assert_eq!(check_ess(HashAlg::Sha256, &hash, Some(&wrong), &der, &c), Err(Rfc3161Error::SigningCertMismatch));
        let other_form = is(vec![GeneralName::DnsName(der::asn1::Ia5String::new("freetsa.org").unwrap())], &c);
        assert_eq!(
            check_ess(HashAlg::Sha256, &hash, Some(&other_form), &der, &c),
            Err(Rfc3161Error::SigningCertMismatch)
        );
        let mut bad_serial = right.clone();
        bad_serial.serial.push(1);
        assert_eq!(
            check_ess(HashAlg::Sha256, &hash, Some(&bad_serial), &der, &c),
            Err(Rfc3161Error::SigningCertMismatch)
        );
    }
}

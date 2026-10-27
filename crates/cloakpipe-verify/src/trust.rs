//! Default trust inputs for the public anchoring services the gate uses
//! unless told otherwise: the freetsa.org and DigiCert TSA roots, and the
//! rekor.sigstore.dev log key. They are public, compiled in from
//! `trust/`, and replaced (not extended) by `--tsa-root` / `--rekor-key`.
//!
//! | file | SHA-256 fingerprint / log ID |
//! |---|---|
//! | `freetsa-root.pem` | `A6:37:9E:7C:…:1D:18:AA:BC` |
//! | `digicert-trusted-root-g4.pem` | `55:2F:7B:DC:…:0A:C8:99:88` |
//! | `rekor.sigstore.dev.pub` | log ID `c0d23d6a…9591801d` |

use crate::rekor::RekorKey;
use crate::rfc3161::TrustedRoots;

const FREETSA_ROOT: &[u8] = include_bytes!("../trust/freetsa-root.pem");
const DIGICERT_ROOT: &[u8] = include_bytes!("../trust/digicert-trusted-root-g4.pem");
const REKOR_PUBLIC_GOOD: &[u8] = include_bytes!("../trust/rekor.sigstore.dev.pub");

/// The freetsa.org and DigiCert Trusted Root G4 certificates.
pub fn default_tsa_roots() -> TrustedRoots {
    TrustedRoots::from_pem(&[FREETSA_ROOT, DIGICERT_ROOT].concat()).expect("the compiled-in TSA roots parse")
}

/// The rekor.sigstore.dev log key.
pub fn default_rekor_key() -> RekorKey {
    RekorKey::from_pem(REKOR_PUBLIC_GOOD).expect("the compiled-in Rekor key parses")
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_defaults_parse_and_name_the_public_good_log() {
        super::default_tsa_roots();
        assert_eq!(
            super::default_rekor_key().log_id_hex(),
            "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
        );
    }
}

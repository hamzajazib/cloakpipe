//! The audit pack's tar container: what `ustar::write` produces is a plain
//! POSIX tar any tool reads, and `ustar::read` accepts only regular files
//! with safe, unique names.

use cloakpipe_verify::ustar::{read, write, TarError};

#[test]
fn files_round_trip_in_order() {
    let big = vec![7u8; 1500];
    let tar = write(&[("pack.json", b"{}".as_slice()), ("anchors/epoch-00000000.json", big.as_slice()), ("empty", b"".as_slice())], 1_700_000_000);
    assert_eq!(tar.len() % 512, 0);
    let files = read(&tar).unwrap();
    let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["pack.json", "anchors/epoch-00000000.json", "empty"]);
    assert_eq!(files[1].data, big);
    assert!(files[2].data.is_empty());
}

#[test]
fn the_system_tar_reads_what_we_write() {
    let Ok(probe) = std::process::Command::new("tar").arg("--version").output() else { return };
    if !probe.status.success() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.tar");
    std::fs::write(&path, write(&[("entries.jsonl", b"{\"seq\":0}\n".as_slice()), ("anchors/a.json", b"[]".as_slice())], 0)).unwrap();
    let out = std::process::Command::new("tar").arg("-tf").arg(&path).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let listed = String::from_utf8_lossy(&out.stdout);
    assert!(listed.contains("entries.jsonl") && listed.contains("anchors/a.json"), "{listed}");
}

fn header_mut(tar: &mut [u8], f: impl FnOnce(&mut [u8])) {
    f(&mut tar[..512]);
    // Re-seal the checksum so only the edit is under test.
    tar[148..156].copy_from_slice(b"        ");
    let sum: u32 = tar[..512].iter().map(|&b| b as u32).sum();
    tar[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}

#[test]
fn a_bad_checksum_is_refused() {
    let mut tar = write(&[("a", b"x".as_slice())], 0);
    tar[0] ^= 1;
    assert!(matches!(read(&tar), Err(TarError::Checksum { .. })));
}

#[test]
fn links_and_devices_are_refused() {
    for flag in *b"12346" {
        let mut tar = write(&[("a", b"".as_slice())], 0);
        header_mut(&mut tar, |h| h[156] = flag);
        assert!(matches!(read(&tar), Err(TarError::Unsupported { .. })), "typeflag {}", flag as char);
    }
}

#[test]
fn unsafe_and_duplicate_names_are_refused() {
    for name in ["../x", "/etc/passwd", "a/../../b", ""] {
        let mut tar = write(&[("placeholder", b"".as_slice())], 0);
        header_mut(&mut tar, |h| {
            h[..100].fill(0);
            h[..name.len()].copy_from_slice(name.as_bytes());
        });
        assert!(matches!(read(&tar), Err(TarError::BadName(_))), "{name:?}");
    }
    let tar = write(&[("a", b"1".as_slice()), ("./a", b"2".as_slice())], 0);
    assert!(matches!(read(&tar), Err(TarError::Duplicate(n)) if n == "a"));
}

#[test]
fn truncation_is_refused() {
    let tar = write(&[("a", [1u8; 700].as_slice())], 0);
    assert!(matches!(read(&tar[..900]), Err(TarError::Truncated)));
    assert!(matches!(read(&tar[..100]), Err(TarError::Truncated)));
}

#[test]
fn directories_are_skipped() {
    let mut tar = write(&[("anchors/", b"".as_slice()), ("anchors/x", b"1".as_slice())], 0);
    header_mut(&mut tar, |h| h[156] = b'5');
    let files = read(&tar).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "anchors/x");
}

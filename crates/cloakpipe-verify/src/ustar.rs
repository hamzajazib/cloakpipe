//! A minimal POSIX ustar reader and writer for audit packs.
//!
//! An audit pack is a plain tar file that any tool can list and unpack.
//! The verifier reads it with this code alone, so it needs no tar crate and
//! no producer code. The reader is strict:
//!
//! - only regular files are read; directories and pax/GNU metadata headers
//!   are skipped, and links, devices and FIFOs are refused;
//! - names are relative, have no `..` component and appear once (a
//!   leading `./` is dropped);
//! - every header checksum is checked, and a truncated archive is refused.

use std::collections::BTreeSet;
use thiserror::Error;

const BLOCK: usize = 512;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TarError {
    #[error("tar archive is truncated")]
    Truncated,
    #[error("tar header at offset {offset} has a bad checksum")]
    Checksum { offset: usize },
    #[error("tar header at offset {offset}: unreadable {field}")]
    Field { offset: usize, field: &'static str },
    #[error("tar member `{name}`: entry type `{typeflag}` is not a regular file")]
    Unsupported { name: String, typeflag: char },
    #[error("tar member name {0:?} is not a safe relative path")]
    BadName(String),
    #[error("tar member `{0}` appears more than once")]
    Duplicate(String),
}

/// One regular file of an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarFile {
    pub name: String,
    pub data: Vec<u8>,
}

/// A ustar archive of `files`, in order, each mode 0644 with modification
/// time `mtime` (Unix seconds). Names must fit ustar's 100 bytes.
pub fn write(files: &[(&str, &[u8])], mtime: u64) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in files {
        assert!(name.len() <= 100, "tar member name too long: {name}");
        let mut h = [0u8; BLOCK];
        h[..name.len()].copy_from_slice(name.as_bytes());
        put_octal(&mut h[100..108], 0o644);
        put_octal(&mut h[108..116], 0);
        put_octal(&mut h[116..124], 0);
        put_octal(&mut h[124..136], data.len() as u64);
        put_octal(&mut h[136..148], mtime);
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(BLOCK) * BLOCK, 0);
    }
    out.resize(out.len() + 2 * BLOCK, 0);
    out
}

/// Zero-padded octal, NUL-terminated, filling `field`.
fn put_octal(field: &mut [u8], v: u64) {
    let s = format!("{v:0width$o}\0", width = field.len() - 1);
    field.copy_from_slice(s.as_bytes());
}

fn parse_octal(field: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(field).ok()?;
    let s = s.trim_matches(|c: char| c == '\0' || c == ' ');
    if s.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(s, 8).ok()
}

fn cstr(field: &[u8]) -> &[u8] {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    &field[..end]
}

/// The regular files of a tar archive, in archive order.
pub fn read(bytes: &[u8]) -> Result<Vec<TarFile>, TarError> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut offset = 0usize;
    loop {
        let Some(h) = bytes.get(offset..offset + BLOCK) else {
            return Err(TarError::Truncated);
        };
        if h.iter().all(|&b| b == 0) {
            // End of archive: one zero block (two in a well-formed file).
            return Ok(out);
        }
        let field = |field: &'static str| TarError::Field { offset, field };
        let recorded = parse_octal(&h[148..156]).ok_or_else(|| field("checksum"))?;
        let sum: u64 = h.iter().enumerate().map(|(i, &b)| if (148..156).contains(&i) { 32 } else { b as u64 }).sum();
        if recorded != sum {
            return Err(TarError::Checksum { offset });
        }
        let size = parse_octal(&h[124..136]).ok_or_else(|| field("size"))? as usize;
        let typeflag = h[156];
        let mut name = String::from_utf8(cstr(&h[..100]).to_vec()).map_err(|_| field("name"))?;
        if &h[257..262] == b"ustar" {
            let prefix = std::str::from_utf8(cstr(&h[345..500])).map_err(|_| field("prefix"))?;
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
        }
        let start = offset + BLOCK;
        let end = start.checked_add(size).ok_or(TarError::Truncated)?;
        let data = bytes.get(start..end).ok_or(TarError::Truncated)?;
        offset = start + size.div_ceil(BLOCK) * BLOCK;
        match typeflag {
            b'0' | 0 | b'7' => {}
            // Directories, pax extended headers and GNU long-name blocks
            // carry no file content of their own.
            b'5' | b'x' | b'g' | b'L' | b'K' => continue,
            t => return Err(TarError::Unsupported { name, typeflag: t as char }),
        }
        let name = clean_name(&name)?;
        if !seen.insert(name.clone()) {
            return Err(TarError::Duplicate(name));
        }
        out.push(TarFile { name, data: data.to_vec() });
    }
}

/// A relative path without `..`, `.` or empty components (a leading `./`
/// is dropped).
fn clean_name(raw: &str) -> Result<String, TarError> {
    let bad = || TarError::BadName(raw.to_string());
    let name = raw.strip_prefix("./").unwrap_or(raw);
    if name.is_empty() || name.starts_with('/') || name.contains('\\') {
        return Err(bad());
    }
    if name.split('/').any(|c| c.is_empty() || c == "." || c == "..") {
        return Err(bad());
    }
    Ok(name.to_string())
}

//! Calendar arithmetic for anchor times, without a date-time dependency.

/// Howard Hinnant's `days_from_civil`: proleptic Gregorian date to days
/// since 1970-01-01.
pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Inverse of [`days_from_civil`].
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        _ => 28,
    }
}

/// Unix seconds for a validated calendar time; `None` if any field is out
/// of range (no leap seconds, no 24:00).
pub(crate) fn unix_from_parts(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> Option<i64> {
    let valid = (1..=12).contains(&mo)
        && d >= 1
        && d <= days_in_month(y, mo)
        && (0..24).contains(&h)
        && (0..60).contains(&mi)
        && (0..60).contains(&s);
    valid.then(|| days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s)
}

/// `YYYY-MM-DDTHH:MM:SSZ`.
pub(crate) fn rfc3339_from_unix(t: i64) -> String {
    let (y, m, d) = civil_from_days(t.div_euclid(86400));
    let s = t.rem_euclid(86400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", s / 3600, s / 60 % 60, s % 60)
}

fn digits(b: &[u8]) -> Option<i64> {
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(b).ok()?.parse().ok()
}

/// Strict RFC 3339 to unix seconds, truncating any fraction:
/// `YYYY-MM-DDTHH:MM:SS[.f+](Z|±HH:MM)`.
pub(crate) fn parse_rfc3339_secs(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let base = unix_from_parts(
        digits(&b[0..4])?,
        digits(&b[5..7])?,
        digits(&b[8..10])?,
        digits(&b[11..13])?,
        digits(&b[14..16])?,
        digits(&b[17..19])?,
    )?;
    let mut rest = &b[19..];
    if let Some(frac) = rest.strip_prefix(b".") {
        let n = frac.iter().take_while(|c| c.is_ascii_digit()).count();
        if n == 0 {
            return None;
        }
        rest = &frac[n..];
    }
    let offset = match rest {
        b"Z" => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let (h, m) = (digits(&[*h1, *h2])?, digits(&[*m1, *m2])?);
            if h > 23 || m > 59 {
                return None;
            }
            let o = h * 3600 + m * 60;
            if *sign == b'+' {
                o
            } else {
                -o
            }
        }
        _ => return None,
    };
    Some(base - offset)
}

/// DER GeneralizedTime content (`YYYYMMDDHHMMSS[.f+]Z`) to unix seconds,
/// truncating any fraction.
pub(crate) fn parse_generalized_time(b: &[u8]) -> Option<i64> {
    if b.len() < 15 || b.last() != Some(&b'Z') {
        return None;
    }
    let body = &b[..b.len() - 1];
    let (whole, frac) = match body.iter().position(|&c| c == b'.') {
        Some(i) => (&body[..i], Some(&body[i + 1..])),
        None => (body, None),
    };
    if whole.len() != 14 || frac.is_some_and(|f| f.is_empty() || !f.iter().all(u8::is_ascii_digit)) {
        return None;
    }
    unix_from_parts(
        digits(&whole[0..4])?,
        digits(&whole[4..6])?,
        digits(&whole[6..8])?,
        digits(&whole[8..10])?,
        digits(&whole[10..12])?,
        digits(&whole[12..14])?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for t in [0, 1_782_993_600, 1_791_374_065, 951_782_400 /* 2000-02-29 */] {
            assert_eq!(parse_rfc3339_secs(&rfc3339_from_unix(t)), Some(t));
        }
        assert_eq!(rfc3339_from_unix(1_782_993_600), "2026-07-02T12:00:00Z");
    }

    #[test]
    fn rfc3339_forms() {
        let t = parse_rfc3339_secs("2026-07-02T12:00:00Z").unwrap();
        assert_eq!(parse_rfc3339_secs("2026-07-02T12:00:00.999Z"), Some(t));
        assert_eq!(parse_rfc3339_secs("2026-07-02T17:30:00+05:30"), Some(t));
        assert_eq!(parse_rfc3339_secs("2026-07-02T12:00:00+00:00"), Some(t));
        for bad in ["", "2026-07-02", "2026-07-02T12:00:00", "2026-13-02T12:00:00Z", "2026-02-30T12:00:00Z",
            "2026-07-02T24:00:00Z", "2026-07-02T12:00:60Z", "2026-07-02T12:00:00.Z", "2026-07-02T12:00:00+5:00",
            "2026-07-02 12:00:00Z", "+026-07-02T12:00:00Z"]
        {
            assert_eq!(parse_rfc3339_secs(bad), None, "{bad}");
        }
    }

    #[test]
    fn generalized_time_forms() {
        let t = parse_rfc3339_secs("2026-10-07T11:58:53Z").unwrap();
        assert_eq!(parse_generalized_time(b"20261007115853Z"), Some(t));
        assert_eq!(parse_generalized_time(b"20261007115853.25Z"), Some(t));
        for bad in [&b"20261007115853"[..], b"202610071158Z", b"20261007115853.Z", b"20261307115853Z",
            b"20261007115853+0000", b"2026100711585aZ"]
        {
            assert_eq!(parse_generalized_time(bad), None);
        }
    }
}

//! Timestamps as the server writes and reads them (ISO 8601), without a
//! date library.

/// Unix seconds as `2026-10-07T19:15:06Z`.
pub fn iso8601(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", secs / 3600, secs % 3600 / 60, secs % 60)
}

/// Unix seconds from a timestamp as Postgres writes it
/// (`2026-10-07T19:15:06.623+00:00`).
pub fn parse_iso8601(text: &str) -> Option<i64> {
    let (date, rest) = text.split_once(['T', ' '])?;
    let mut parts = date.split('-');
    let (year, month, day) = (parts.next()?.parse().ok()?, parts.next()?.parse().ok()?, parts.next()?.parse().ok()?);
    let zone_at = rest.find(['Z', '+', '-']).unwrap_or(rest.len());
    let (clock, zone) = rest.split_at(zone_at);
    let mut clock = clock.split(':');
    let hours: i64 = clock.next()?.parse().ok()?;
    let minutes: i64 = clock.next()?.parse().ok()?;
    let seconds: i64 = clock.next().unwrap_or("0").split('.').next()?.parse().ok()?;
    let offset = match zone {
        "" | "Z" => 0,
        _ => {
            let sign = if zone.starts_with('-') { -1 } else { 1 };
            let mut z = zone[1..].split(':');
            let (h, m): (i64, i64) = (z.next()?.parse().ok()?, z.next().unwrap_or("0").parse().ok()?);
            sign * (h * 3600 + m * 60)
        }
    };
    Some(crate::health::unix_day(year, month, day) + hours * 3600 + minutes * 60 + seconds - offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(1_791_400_506), "2026-10-07T19:15:06Z");
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(parse_iso8601("2026-10-07T19:15:06.623+00:00"), Some(1_791_400_506));
        assert_eq!(parse_iso8601("2026-10-07T16:15:06-03:00"), Some(1_791_400_506));
        assert_eq!(parse_iso8601("2026-10-07 19:15:06Z"), Some(1_791_400_506));
        assert_eq!(parse_iso8601(&iso8601(1_700_000_123)), Some(1_700_000_123));
        assert_eq!(parse_iso8601("garbage"), None);
    }
}

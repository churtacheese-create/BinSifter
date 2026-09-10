//! IOC extraction from FLOSS strings - regex-mined IPs, URLs, domains, and
//! registry paths. Direct port of `binsifter.core.iocs`.
//!
//! The four patterns are translated 1:1 from the PowerShell version and are
//! **deliberately not "improved"**, even where they have quirks - matching
//! the other variants' output for the same input matters more than a
//! cleaner regex:
//!
//! * none of the patterns are case-insensitive, so the domain pattern
//!   (lowercase character classes) only matches all-lowercase domains and
//!   the URL pattern only matches a lowercase `http`/`https` scheme.
//! * dedup is case-insensitive but the first-seen casing is kept; domain
//!   matches are lowercased before insertion.
//! * insertion order (IP, then URL, then domain, then registry, per string,
//!   in list order) is preserved for the first 50 entries in the display.

use std::sync::LazyLock;

use regex::Regex;

static IP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap()
});
static URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\bhttps?://[^\s"'<>]{4,200}"#).unwrap());
static DOMAIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|biz|info|xyz|top|club|online|site|tk|cc)\b").unwrap()
});
static REGISTRY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\bHKEY_[A-Z_]+\\[^\s"']{2,200}"#).unwrap());

const MAX_DISPLAYED_IOCS: usize = 50;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IocExtractionResult {
    pub count: usize,
    /// `"; "`-joined, capped at [`MAX_DISPLAYED_IOCS`]; `""` if none.
    pub display: String,
}

/// Mine already-extracted strings for IOC-shaped values. Never errors.
pub fn extract_iocs<S: AsRef<str>>(strings: &[S]) -> IocExtractionResult {
    // lowercased key -> first-seen-cased display value, insertion-ordered
    let mut seen: Vec<(String, String)> = Vec::new();
    let mut add = |value: String| {
        let key = value.to_lowercase();
        if !seen.iter().any(|(k, _)| *k == key) {
            seen.push((key, value));
        }
    };

    for s in strings {
        let s = s.as_ref();
        if s.is_empty() {
            continue;
        }
        for m in IP_RE.find_iter(s) {
            add(m.as_str().to_string());
        }
        for m in URL_RE.find_iter(s) {
            add(m.as_str().to_string());
        }
        for m in DOMAIN_RE.find_iter(s) {
            add(m.as_str().to_lowercase());
        }
        for m in REGISTRY_RE.find_iter(s) {
            add(m.as_str().to_string());
        }
    }

    let count = seen.len();
    if count == 0 {
        return IocExtractionResult {
            count: 0,
            display: String::new(),
        };
    }
    let display = seen
        .iter()
        .take(MAX_DISPLAYED_IOCS)
        .map(|(_, v)| v.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    IocExtractionResult { count, display }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_all_kinds_in_first_seen_order() {
        let strings = vec![
            "connect to 192.168.1.5 then GET https://evil.example.com/payload".to_string(),
            "reg key HKEY_LOCAL_MACHINE\\Software\\Run\\x also c2.bad.top here".to_string(),
        ];
        let r = extract_iocs(&strings);
        // string 1: IP, URL, domain(from the URL host); string 2: domain, registry
        assert_eq!(r.count, 5);
        let parts: Vec<&str> = r.display.split("; ").collect();
        assert_eq!(parts[0], "192.168.1.5");
        assert_eq!(parts[1], "https://evil.example.com/payload");
        assert_eq!(parts[2], "evil.example.com");
        assert_eq!(parts[3], "c2.bad.top");
        assert_eq!(parts[4], "HKEY_LOCAL_MACHINE\\Software\\Run\\x");
    }

    #[test]
    fn case_insensitive_dedup_keeps_first_casing() {
        let s = vec![
            "HTTP is not matched but http://Site.example.io/A".to_string(),
            "again http://site.example.io/a".to_string(),
        ];
        let r = extract_iocs(&s);
        // the two URLs differ only in case -> one entry, first casing kept
        // (but each also yields a domain match, lowercased)
        assert!(r.display.contains("http://Site.example.io/A"));
        assert!(!r.display.contains("http://site.example.io/a"));
    }

    #[test]
    fn uppercase_domain_and_scheme_not_matched_quirk() {
        let r = extract_iocs(&["visit HTTPS://BAD.COM now".to_string()]);
        assert_eq!(
            r.count, 0,
            "uppercase scheme/domain deliberately not matched"
        );
    }

    #[test]
    fn empty_and_none() {
        assert_eq!(extract_iocs::<String>(&[]).count, 0);
        assert_eq!(extract_iocs(&["nothing here".to_string()]).display, "");
    }

    #[test]
    fn display_capped_at_50() {
        let s: Vec<String> = (0..80).map(|i| format!("10.0.0.{i}")).collect();
        let r = extract_iocs(&s);
        assert_eq!(r.count, 80);
        assert_eq!(r.display.split("; ").count(), 50);
    }
}

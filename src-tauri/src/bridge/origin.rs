//! Exact web-origin matching (issue #16).
//!
//! A login matches a tab only if scheme, host and port are all equal after
//! normalization: lower case, IDNA to punycode (so look-alike Unicode hosts
//! never equal their ASCII twin), default ports made explicit, and a single
//! trailing dot removed. There is no suffix or "registrable domain" matching:
//! `github.com.evil.test`, `evil-github.com` and `http://github.com` never
//! match `https://github.com`.

use url::{Host, Url};

/// A normalized `scheme://host:port` origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

impl Origin {
    /// Parses the origin of a browser tab. Only `http` and `https` are
    /// accepted; credentials in the URL are refused.
    pub fn parse_tab(s: &str) -> Option<Self> {
        Self::from_url(&Url::parse(s.trim()).ok()?)
    }

    /// Parses a stored item URL. A bare host (`github.com/login`) is read as
    /// `https://`, which is how the item editor and importers store them.
    pub fn parse_item(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let url = match Url::parse(s) {
            Ok(u) if s.contains("://") => u,
            _ => Url::parse(&format!("https://{s}")).ok()?,
        };
        Self::from_url(&url)
    }

    fn from_url(url: &Url) -> Option<Self> {
        let scheme = url.scheme();
        if scheme != "https" && scheme != "http" {
            return None;
        }
        if !url.username().is_empty() || url.password().is_some() {
            return None;
        }
        let host = match url.host()? {
            Host::Domain(d) => {
                let d = d.strip_suffix('.').unwrap_or(d);
                if d.is_empty() || d.ends_with('.') {
                    return None;
                }
                d.to_ascii_lowercase()
            }
            Host::Ipv4(ip) => ip.to_string(),
            Host::Ipv6(ip) => format!("[{ip}]"),
        };
        Some(Self {
            scheme: scheme.to_string(),
            host,
            port: url.port_or_known_default()?,
        })
    }
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}:{}", self.scheme, self.host, self.port)
    }
}

/// Whether the stored item URL belongs to exactly the tab's origin.
pub fn item_matches(item_url: &str, tab: &Origin) -> bool {
    Origin::parse_item(item_url).is_some_and(|o| &o == tab)
}

/// Like [`item_matches`], but the tab may also be a subdomain of the item's
/// host (issue #152). Scheme and port must still be equal; the item host must
/// be a DNS name with at least one dot (never an IP address or a bare label
/// such as `com`), and the match is on a whole label boundary, so
/// `evil-github.com` and `github.com.evil.test` still fail.
pub fn item_matches_subdomains(item_url: &str, tab: &Origin) -> bool {
    let Some(o) = Origin::parse_item(item_url) else {
        return false;
    };
    if o == *tab {
        return true;
    }
    // An IPv4 literal ends in a numeric label; a DNS name's TLD never does.
    let is_name = o.host.contains('.')
        && !o.host.starts_with('[')
        && o.host
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.chars().any(|c| !c.is_ascii_digit()));
    is_name
        && o.scheme == tab.scheme
        && o.port == tab.port
        && tab
            .host
            .strip_suffix(o.host.as_str())
            .is_some_and(|rest| rest.ends_with('.') && rest.len() > 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tab(s: &str) -> Origin {
        Origin::parse_tab(s).unwrap_or_else(|| panic!("tab {s}"))
    }

    #[test]
    fn matches_table() {
        let gh = tab("https://github.com/login?return_to=x");
        let cases: &[(&str, bool)] = &[
            ("https://github.com", true),
            ("https://github.com/", true),
            ("https://GitHub.COM/settings", true),
            ("github.com", true), // bare host = https
            ("github.com/login", true),
            ("https://github.com:443/", true),  // default port
            ("https://github.com./", true),     // trailing dot
            ("http://github.com", false),       // scheme
            ("https://github.com:8443", false), // port
            ("https://github.com.evil.test", false),
            ("https://evil-github.com", false),
            ("https://gist.github.com", false), // no implicit subdomains
            ("https://user:pw@github.com", false),
            ("https://gíthub.com", false), // Unicode look-alike
            ("ftp://github.com", false),
            ("", false),
            ("not a url at all", false),
        ];
        for (item, want) in cases {
            assert_eq!(item_matches(item, &gh), *want, "{item}");
        }
    }

    #[test]
    fn subdomain_opt_in_table() {
        let cases: &[(&str, &str, bool)] = &[
            ("github.com", "https://gist.github.com/x", true),
            ("github.com", "https://a.b.github.com", true),
            ("github.com", "https://github.com", true),
            ("https://github.com", "http://gist.github.com", false),
            ("github.com", "https://gist.github.com:8443", false),
            ("github.com", "https://evil-github.com", false),
            ("github.com", "https://github.com.evil.test", false),
            ("github.com", "https://xgithub.com", false),
            ("github.com", "https://.github.com", false),
            ("com", "https://evil.com", false),
            ("localhost", "https://a.localhost", false),
            ("10.0.0.1", "https://1.10.0.0.1", false),
            ("gist.github.com", "https://github.com", false),
        ];
        for (item, t, want) in cases {
            let tb = match Origin::parse_tab(t) {
                Some(o) => o,
                None => {
                    assert!(!*want, "{t}");
                    continue;
                }
            };
            assert_eq!(item_matches_subdomains(item, &tb), *want, "{item} vs {t}");
            // Exact matching never widens.
            if *item == "github.com" && *t == "https://gist.github.com/x" {
                assert!(!item_matches(item, &tb));
            }
        }
    }

    #[test]
    fn idna_lookalike_is_its_own_origin() {
        let fake = tab("https://gíthub.com/");
        assert_ne!(fake, tab("https://github.com/"));
        // Stored either as Unicode or as its punycode, it is the same origin.
        let puny = fake.to_string().replace(":443", "");
        assert!(puny.starts_with("https://xn--"), "{puny}");
        assert!(item_matches(&puny, &fake));
        assert!(item_matches("gíthub.com", &fake));
    }

    #[test]
    fn tab_origins_must_be_web() {
        for s in [
            "file:///C:/x.html",
            "chrome-extension://abc/popup.html",
            "javascript:alert(1)",
            "data:text/html,hi",
            "https://u:p@github.com",
            "github.com", // a tab URL always has a scheme
        ] {
            assert!(Origin::parse_tab(s).is_none(), "{s}");
        }
        assert_eq!(
            tab("http://127.0.0.1:8080/x").to_string(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(tab("https://[::1]/").to_string(), "https://[::1]:443");
    }
}

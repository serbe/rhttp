use crate::error::{Error, Result};
// use std::net::{SocketAddr, ToSocketAddrs};

#[derive(Debug, Default, PartialEq)]
pub struct Url<'a> {
    scheme: Option<&'a str>,
    opaque: Option<&'a str>,
    user: Option<&'a str>,
    password: Option<&'a str>,
    host: &'a str,
    port: Option<&'a str>,
    path: Option<&'a str>,
    query: Option<&'a str>,
    fragment: Option<&'a str>,
}

impl<'a> Url<'a> {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn from(rawurl: &'static str) -> Result<Self> {
        if rawurl == "" {
            Err(Error::Empty())?;
        }

        check_contains_ctl_byte(rawurl)?;

        let mut url = Url::default();

        if rawurl == "*" {
            url.path = Some(rawurl);
            return Ok(url);
        }

        url.scheme = get_scheme(rawurl)?;

        let raw = if let Some(part) = get_part(rawurl, url.scheme, 1) {
            part
        } else {
            rawurl
        };

        let (raw, query) = if let Some(pos) = raw.find('?') {
            (
                raw.get(..pos).ok_or_else(|| Error::ParseQuery(raw))?,
                raw.get(pos + 1..),
            )
        } else {
            (raw, None)
        };

        url.query = query;

        let slash = raw.find('/');

        if slash.is_none() {
            if url.scheme.is_none() {
                url.opaque = Some(raw);
                return Ok(url);
            }

            let colon = raw.find(':');
            if colon.is_some() && (slash.is_none() || colon < slash) {
                return Err(Error::NotContainColon(raw));
            }
        }

        let (raw, fragment) = if let Some(pos) = raw.find('#') {
            (
                raw.get(..pos).ok_or_else(|| Error::ParseFragment(raw))?,
                raw.get(pos + 1..),
            )
        } else {
            (raw, None)
        };

        url.fragment = fragment;

        let raw = if raw.starts_with("//") {
            raw.get(2..).unwrap()
        } else {
            raw
        };

        let (raw, user, password) = if let Some(pos) = raw.find('@') {
            let new_raw = raw
                .get(pos + 1..)
                .ok_or_else(|| Error::ParseUserInfo(raw))?;
            let userinfo = raw.get(..pos);
            match userinfo {
                Some(user) => {
                    if let Some(pos) = user.find(':') {
                        (new_raw, user.get(..pos), user.get(pos + 1..))
                    } else {
                        (new_raw, Some(user), None)
                    }
                }
                None => (new_raw, None, None),
            }
        } else {
            (raw, None, None)
        };

        url.user = user;
        url.password = password;

        let (raw, path) = if let Some(pos) = raw.find('/') {
            (
                raw.get(..pos).ok_or_else(|| Error::ParsePath(raw))?,
                raw.get(pos..),
            )
        } else {
            (raw, None)
        };

        url.path = path;

        let (host, port) = if let Some(pos) = raw.rfind(':') {
            if let Some(start) = raw.find('[') {
                if let Some(end) = raw.find(']') {
                    if start == 0 && pos == end + 1 {
                        (
                            raw.get(..pos).ok_or_else(|| Error::ParseHost(raw))?,
                            raw.get(pos + 1..),
                        )
                    } else if start == 0 && end == raw.len() - 1 {
                        (raw, None)
                    } else {
                        Err(Error::ParseIPv6(raw))?
                    }
                } else {
                    Err(Error::ParseIPv6(raw))?
                }
            } else {
                (
                    raw.get(..pos).ok_or_else(|| Error::ParseHost(raw))?,
                    raw.get(pos + 1..),
                )
            }
        } else {
            (raw, None)
        };

        url.host = host;
        url.port = port;

        if let Some(port) = port {
            let _ = port.parse::<u32>().map_err(|_| Error::ParsePort(raw))?;
        }

        Ok(url)
    }

    pub fn scheme(&self) -> Option<String> {
        if let Some(scheme) = self.scheme {
            Some(scheme.to_lowercase())
        } else {
            None
        }
    }

    pub fn origin(&self) -> String {
        format!(
            "{}://{}:{}",
            self.default_scheme(),
            self.host,
            self.default_port()
        )
    }

    pub fn default_scheme(&self) -> String {
        if let Some(scheme) = self.scheme() {
            scheme
        } else if let Some(port) = self.port {
            match port {
                "21" => "ftp",
                "22" => "ssh",
                "23" => "telnet",
                "80" => "http",
                "110" => "pop",
                "111" => "nfs",
                "143" => "imap",
                "161" => "snmp",
                "194" => "irc",
                "389" => "ldap",
                "443" => "https",
                "445" => "smb",
                "636" => "ldaps",
                "873" => "rsync",
                "5900" => "vnc",
                "6379" => "redis",
                "9418" => "git",
                _ => "http",
            }
            .to_string()
        } else {
            String::from("http")
        }
    }

    pub fn default_port(&self) -> String {
        if let Some(port) = self.port {
            port.to_string()
        } else if let Some(scheme) = self.scheme() {
            match scheme.as_str() {
                "ftp" => "21",
                "git" => "9418",
                "http" => "80",
                "https" => "443",
                "imap" => "143",
                "irc" => "194",
                "ldap" => "389",
                "ldaps" => "636",
                "nfs" => "111",
                "pop" => "110",
                "redis" => "6379",
                "rsync" => "873",
                "sftp" => "22",
                "smb" => "445",
                "snmp" => "161",
                "ssh" => "22",
                "telnet" => "23",
                "vnc" => "5900",
                "ws" => "80",
                "wss" => "443",
                _ => "80",
            }
            .to_string()
        } else {
            String::from("80")
        }
    }
}

// impl Userinfo {
//     pub fn new() -> Self {
//         Default::default()
//     }

//     pub fn from_user(username: String) -> Self {
//         Userinfo {
//             username,
//             password: String::new(),
//             password_set: false,
//         }
//     }

//     pub fn from_user_password(username: String, password: String) -> Self {
//         Userinfo {
//             username,
//             password,
//             password_set: true,
//         }
//     }

//     fn to_string(&self) -> String {
//         if self.password_set {
//             format!("{}:{}", self.username, self.password)
//         } else {
//             String::from(&self.username)
//         }
//     }
// }

fn get_scheme(rawurl: &'static str) -> Result<Option<&'static str>> {
    for (i, c) in rawurl.to_lowercase().chars().enumerate() {
        if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' {
        } else if '0' <= c && c <= '9' || c == '+' || c == '-' || c == '.' {
            if i == 0 {
                return Ok(None);
            }
        } else if c == ':' {
            if i == 0 {
                return Err(Error::MissingScheme("missing protocol scheme"));
            }
            return Ok(rawurl.get(..i));
        } else {
            return Ok(None);
        }
    }
    Ok(None)
}

fn check_contains_ctl_byte(s: &'static str) -> Result<()> {
    if s.bytes().any(|c| c < 32 || c == 0x7f) {
        Err(Error::ContainsCTLByte(s))
    } else {
        Ok(())
    }
}

fn get_part<'a>(s: &'a str, part: Option<&'a str>, shift: usize) -> Option<&'a str> {
    if let Some(part) = part {
        if let Some(i) = s.find(part) {
            s.get(i + shift + part.len()..)
        } else {
            None
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_path() {
        let s = Url::from("http://www.example.org").unwrap();
        let mut u = Url::new();
        u.scheme = Some("http");
        u.host = "www.example.org";
        assert_eq!(s, u);
    }

    #[test]
    fn with_path() {
        let s = Url::from("http://www.example.org/").unwrap();
        let mut u = Url::new();
        u.scheme = Some("http");
        u.host = "www.example.org";
        u.path = Some("/");
        assert_eq!(s, u);
    }

    // #[test]
    // fn path_with_hex_escaping() {
    // 	let mut u = Url::new();
    // 	let s = Url::from("http://www.example.org/file%20one%26two").unwrap();
    // 	u.scheme = Some("http");
    // 	u.host = "www.example.org";
    // 	// u.path = Some("/file one&two");
    // 	u.path = Some("/file%20one%26two");
    // 	assert_eq!(s, u);
    // }

    #[test]
    fn user() {
        let mut u = Url::new();
        let s = Url::from("ftp://webmaster@www.example.org/").unwrap();
        u.scheme = Some("ftp");
        u.user = Some("webmaster");
        u.host = "www.example.org";
        u.path = Some("/");
        assert_eq!(s, u);
    }

    // #[test]
    // fn escape_sequence_in_username() {
    // 	let mut u = Url::new();
    // 	let s = Url::from("ftp://john%20doe@www.example.org/").unwrap();
    // 	u.scheme = Some("ftp");
    // 	// u.user = Some("john doe");
    // 	u.user = Some("john%20doe");
    // 	u.host = "www.example.org";
    // 	u.path = Some("/");
    // 	assert_eq!(s, u);
    // }

    #[test]
    fn empty_query() {
        let mut u = Url::new();
        let s = Url::from("http://www.example.org/?").unwrap();
        u.scheme = Some("http");
        u.host = "www.example.org";
        u.path = Some("/");
        u.query = Some("");
        assert_eq!(s, u);
    }

    #[test]
    fn query_ending_in_question_mark() {
        let mut u = Url::new();
        let s = Url::from("http://www.example.org/?foo=bar?").unwrap();
        u.scheme = Some("http");
        u.host = "www.example.org";
        u.path = Some("/");
        u.query = Some("foo=bar?");
        assert_eq!(s, u);
    }

    #[test]
    fn query() {
        let mut u = Url::new();
        let s = Url::from("http://www.example.org/?q=rust+language").unwrap();
        u.scheme = Some("http");
        u.host = "www.example.org";
        u.path = Some("/");
        u.query = Some("q=rust+language");
        assert_eq!(s, u);
    }

    // #[test]
    // fn query_with_hex_escaping() {
    //     let mut u = Url::new();
    //     let s = Url::from("http://www.example.org/?q=go%20language").unwrap();
    //     u.scheme = Some("http");
    //     u.host = "www.example.org";
    //     u.path = Some("/");
    //     u.query = Some("q=go%20language");
    //     assert_eq!(s, u);
    // }

    // #[test]
    // fn outside_query() {
    //     let mut u = Url::new();
    //     let s = Url::from("http://www.example.org/a%20b?q=c+d").unwrap();
    //     u.scheme = Some("http");
    //     u.host = "www.example.org";
    //     u.path = Some("/a b");
    //     u.query = Some("q=c+d");
    //     assert_eq!(s, u);
    // }

    #[test]
    fn path_without_leading2() {
        let mut u = Url::new();
        let s = Url::from("http://www.example.org/?q=rust+language").unwrap();
        u.scheme = Some("http");
        u.host = "www.example.org";
        u.path = Some("/");
        u.query = Some("q=rust+language");
        assert_eq!(s, u);
    }

    // #[test]
    // fn path_without_leading() {
    //     let mut u = Url::new();
    //     let s = Url::from("http:%2f%2fwww.example.org/?q=rust+language").unwrap();
    //     u.scheme = Some("http");
    //     // Opaque:   "%2f%2fwww.example.org/",
    //     u.query = Some("q=rust+language");
    //     assert_eq!(s, u);
    // }

    #[test]
    fn non() {
        let mut u = Url::new();
        let s = Url::from("mailto://webmaster@example.org").unwrap();
        u.scheme = Some("mailto");
        u.user = Some("webmaster");
        u.host = "example.org";
        assert_eq!(s, u);
    }

    #[test]
    fn unescaped() {
        let mut u = Url::new();
        let s = Url::from("/foo?query=http://bad").unwrap();
        u.path = Some("/foo");
        u.query = Some("query=http://bad");
        assert_eq!(s, u);
    }

    #[test]
    fn leading() {
        let mut u = Url::new();
        let s = Url::from("//foo").unwrap();
        u.host = "foo";
        assert_eq!(s, u);
    }

    #[test]
    fn leading2() {
        let mut u = Url::new();
        let s = Url::from("user@foo/path?a=b").unwrap();
        u.user = Some("user");
        u.host = "foo";
        u.path = Some("/path");
        u.query = Some("a=b");
        assert_eq!(s, u);
    }

    #[test]
    fn same_codepath() {
        let mut u = Url::new();
        let s = Url::from("/threeslashes").unwrap();
        u.path = Some("/threeslashes");
        assert_eq!(s, u);
    }

    // #[test]
    // fn relative_path() {
    // 	let mut u = Url::new();
    // 	let s = Url::from("a/b/c").unwrap();
    // 	u.path = Some("a/b/c");
    // 	assert_eq!(s, u);
    // }

    // #[test]
    // fn escaped() {
    //     let mut u = Url::new();
    //     let s = Url::from("http://%3Fam:pa%3Fsword@google.com").unwrap();
    //     u.scheme = Some("http");
    //     u.user = Some("?am");
    //     u.password = Some("pa?sword");
    //     u.host = "google.com";
    //     assert_eq!(s, u);
    // }

    #[test]
    fn host_subcomponent() {
        let mut u = Url::new();
        let s = Url::from("http://192.168.0.1/").unwrap();
        u.scheme = Some("http");
        u.host = "192.168.0.1";
        u.path = Some("/");
        assert_eq!(s, u);
    }

    #[test]
    fn host_and_port_subcomponents() {
        let mut u = Url::new();
        let s = Url::from("http://192.168.0.1:8080/").unwrap();
        u.scheme = Some("http");
        u.host = "192.168.0.1";
        u.port = Some("8080");
        u.path = Some("/");
        assert_eq!(s, u);
    }

    #[test]
    fn host_subcomponent2() {
        let mut u = Url::new();
        let s = Url::from("http://[fe80::1]/").unwrap();
        u.scheme = Some("http");
        u.host = "[fe80::1]";
        u.path = Some("/");
        assert_eq!(s, u);
    }

    #[test]
    fn host_and_port_subcomponents2() {
        let mut u = Url::new();
        let s = Url::from("http://[fe80::1]:8080/").unwrap();
        u.scheme = Some("http");
        u.host = "[fe80::1]";
        u.port = Some("8080");
        u.path = Some("/");
        assert_eq!(s, u);
    }

    // #[test]
    // fn host_subcomponent3() {
    //     let mut u = Url::new();
    //     let s = Url::from("http://[fe80::1%25en0]/").unwrap();
    //     u.scheme = Some("http");
    //     u.host = "[fe80::1%en0]";
    //     u.path = Some("/");
    //     assert_eq!(s, u);
    // }

    // #[test]
    // fn host_and_port_subcomponents3() {
    //     let mut u = Url::new();
    //     let s = Url::from("http://[fe80::1%25en0]:8080/").unwrap();
    //     u.scheme = Some("http");
    //     u.host = "[fe80::1%en0]";
    //     u.port = Some("8080");
    //     u.path = Some("/");
    //     assert_eq!(s, u);
    // }

    // #[test]
    // fn host_subcomponent4() {
    //     let mut u = Url::new();
    //     let s = Url::from("http:[fe80::1%25%65%6e%301-._~]/").unwrap();
    //     u.scheme = Some("http");
    //     u.host = "[fe80::1%en01-._~]";
    //     u.path = Some("/");
    //     assert_eq!(s, u);
    // }

    // #[test]
    // fn host_and_port_subcomponents4() {
    //     let mut u = Url::new();
    //     let s = Url::from("http:[fe80::1%25%65%6e%301-._~]:8080/").unwrap();
    //     u.scheme = Some("http");
    //     u.host = "[fe80::1%en01-._~]";
    //     u.port = Some("8080");
    //     u.path = Some("/");
    //     assert_eq!(s, u);
    // }

    // #[test]
    // fn alternate_escapings_of_path_survive_round_trip() {
    //     let mut u = Url::new();
    //     let s = Url::from("http://rest.rsc.io/foo%2fbar/baz%2Fquux?alt=media").unwrap();
    //     u.scheme = Some("http");
    //     u.host = "rest.rsc.io";
    //     u.path = Some("/foo/bar/baz/quux");
    //     // Rawu.path = Some("/foo%2fbar/baz%2Fquux");
    //     u.query = Some("alt=media");
    //     assert_eq!(s, u);
    // }

    #[test]
    fn issue_12036() {
        let mut u = Url::new();
        let s = Url::from("mysql://a,b,c/bar").unwrap();
        u.scheme = Some("mysql");
        u.host = "a,b,c";
        u.path = Some("/bar");
        assert_eq!(s, u);
    }

    // #[test]
    // fn worst_case_host() {
    //     let mut u = Url::new();
    //     let s = Url::from("scheme://!$&'()*+,;=hello!:port/path").unwrap();
    //     u.scheme = Some("scheme");
    //     u.host = "!$&'()*+,;=hello!";
    //     u.port = Some(":port");
    //     u.path = Some("/path");
    //     assert_eq!(s, u);
    // }

    // #[test]
    // fn worst_case_path() {
    //     let mut u = Url::new();
    //     let s = Url::from("http://host/!$&'()*+,;=:@[hello]").unwrap();
    //     u.scheme = Some("http");
    //     u.host = "host";
    //     u.path = Some("/!$&'()*+,;=:@[hello]");
    //     // Rawu.path = Some("/!$&'()*+,;=:@[hello]");
    //     assert_eq!(s, u);
    // }

    #[test]
    fn example() {
        let mut u = Url::new();
        let s = Url::from("http://example.com/oid/[order_id]").unwrap();
        u.scheme = Some("http");
        u.host = "example.com";
        u.path = Some("/oid/[order_id]");
        // Rawu.path = Some("/oid/[order_id]");
        assert_eq!(s, u);
    }

    #[test]
    fn example2() {
        let mut u = Url::new();
        let s = Url::from("http://192.168.0.2:8080/foo").unwrap();
        u.scheme = Some("http");
        u.host = "192.168.0.2";
        u.port = Some("8080");
        u.path = Some("/foo");
        assert_eq!(s, u);
    }

    //      let mut u = Url::new();
    //      let s = Url::from("http://192.168.0.2:/foo").unwrap();
    //      		u.scheme = Some("http");
    //      		u.host = "192.168.0.2:";
    //      		u.path = Some("/foo");
    //      assert_eq!(s, u);
    // }

    //      let mut u = Url::new();
    //      	 Malformed IPv6 but still accepted.
    //      let s = Url::from("http://2b01:e34:ef40:7730:8e70:5aff:fefe:edac:8080/foo").unwrap();
    //      		u.scheme = Some("http");
    //      		u.host = "2b01:e34:ef40:7730:8e70:5aff:fefe:edac:8080";
    //      		u.path = Some("/foo");
    //      assert_eq!(s, u);
    // }

    //      let mut u = Url::new();
    //      	 Malformed IPv6 but still accepted.
    //      let s = Url::from("http://2b01:e34:ef40:7730:8e70:5aff:fefe:edac:/foo").unwrap();
    //      		u.scheme = Some("http");
    //      		u.host = "2b01:e34:ef40:7730:8e70:5aff:fefe:edac:";
    //      		u.path = Some("/foo");
    //      assert_eq!(s, u);
    // }

    //      let mut u = Url::new();
    //      let s = Url::from("http:[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:8080/foo").unwrap();
    //      		u.scheme = Some("http");
    //      		u.host = "[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:8080";
    //      		u.path = Some("/foo");
    //      assert_eq!(s, u);
    // }

    //      let mut u = Url::new();
    //      let s = Url::from("http:[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:/foo").unwrap();
    //      		u.scheme = Some("http");
    //      		u.host = "[2b01:e34:ef40:7730:8e70:5aff:fefe:edac]:";
    //      		u.path = Some("/foo");
    //      assert_eq!(s, u);
    // }

    #[test]
    fn example3() {
        let mut u = Url::new();
        let s = Url::from("http://hello.世界.com/foo").unwrap();
        u.scheme = Some("http");
        u.host = "hello.世界.com";
        u.path = Some("/foo");
        assert_eq!(s, u);
    }

    //      let mut u = Url::new();
    //      let s = Url::from("http://hello.%e4%b8%96%e7%95%8c.com/foo").unwrap();
    //      		u.scheme = Some("http");
    //      		u.host = "hello.世界.com";
    //      		u.path = Some("/foo");
    //      assert_eq!(s, u);
    //      let s = Url::from("http://hello.%E4%B8%96%E7%95%8C.com/foo").unwrap();
    //      }

    //      let mut u = Url::new();
    //      let s = Url::from("http://hello.%E4%B8%96%E7%95%8C.com/foo").unwrap();
    //      		u.scheme = Some("http");
    //      		u.host = "hello.世界.com";
    //      		u.path = Some("/foo");
    //      assert_eq!(s, u);
    // }

    #[test]
    fn example4() {
        let mut u = Url::new();
        let s = Url::from("http://example.com//foo").unwrap();
        u.scheme = Some("http");
        u.host = "example.com";
        u.path = Some("//foo");
        assert_eq!(s, u);
    }

    #[test]
    fn test_that_we_can_reparse_the_host_names_we_accept() {
        let mut u = Url::new();
        let s = Url::from("myscheme://authority<\"hi\">/foo").unwrap();
        u.scheme = Some("myscheme");
        u.host = "authority<\"hi\">";
        u.path = Some("/foo");
        assert_eq!(s, u);
    }

    // #[test]
    // fn example5() {
    //     let mut u = Url::new();
    //     let s = Url::from("tcp:[2020::2020:20:2020:2020%25Windows%20Loves%20Spaces]:2020").unwrap();
    //     u.scheme = Some("tcp");
    //     u.host = "[2020::2020:20:2020:2020%Windows Loves Spaces]:2020";
    //     assert_eq!(s, u);
    // }
}

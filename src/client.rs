use std::io;

use url::Url;

use crate::error::{Error, Result};
use crate::http::HttpStream;
use crate::socks::SocksStream;

pub enum Client {
    Http(HttpStream),
    Socks(SocksStream),
}

impl Client {
    pub fn connect(target: &str) -> Result<Self> {
        Ok(Client::Http(HttpStream::connect(target)?))
    }

    pub fn connect_proxy(proxy_with_scheme: &str, target: &str) -> Result<Self> {
        let proxy_url = Url::parse(proxy_with_scheme).map_err(Error::UrlParse)?;
        let scheme = proxy_url.scheme();
        if scheme == "http" || scheme == "https" {
            Client::connect_http(proxy_with_scheme, target)
        } else if scheme == "socks5" || scheme == "socks5h" || scheme == "socks5t" {
            Client::connect_socks(proxy_with_scheme, target)
        } else {
            Err(Error::UnsupportedProxy)
        }
    }

    pub fn connect_http(proxy: &str, target: &str) -> Result<Self> {
        Ok(Client::Http(HttpStream::connect_proxy(proxy, target)?))
    }

    pub fn connect_socks(proxy: &str, target: &str) -> Result<Self> {
        Ok(Client::Socks(SocksStream::connect(proxy, target)?))
    }

    pub fn connect_socks_auth(
        proxy: &str,
        target: &str,
        username: &str,
        password: &str,
    ) -> Result<Self> {
        Ok(Client::Socks(SocksStream::connect_plain(
            proxy, target, username, password,
        )?))
    }

    pub fn get(&mut self) -> io::Result<Vec<u8>> {
        match self {
            Client::Http(http) => http.get(),
            Client::Socks(socks) => socks.get(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_http() {
        let mut client = Client::connect("http://api.ipify.org").unwrap();
        let body = client.get().unwrap();
        let txt = String::from_utf8_lossy(&body);
        assert!(txt.contains(crate::tests::IP.as_str()));
    }

    #[test]
    fn client_https() {
        let mut client = Client::connect("https://api.ipify.org").unwrap();
        let body = client.get().unwrap();
        let txt = String::from_utf8_lossy(&body);
        assert!(txt.contains(crate::tests::IP.as_str()));
    }

    #[test]
    fn client_http_proxy() {
        let mut client =
            Client::connect_proxy("http://127.0.0.1:5858", "https://api.ipify.org").unwrap();
        let body = client.get().unwrap();
        let txt = String::from_utf8_lossy(&body);
        assert!(txt.contains(crate::tests::IP.as_str()));
    }

    #[test]
    fn client_socks() {
        let mut client =
            Client::connect_proxy("socks5://127.0.0.1:5959", "https://api.ipify.org").unwrap();
        let body = client.get().unwrap();
        let txt = String::from_utf8_lossy(&body);
        assert!(txt.contains(crate::tests::IP.as_str()));
    }

    #[test]
    fn client_socks_auth() {
        let mut client =
            Client::connect_socks_auth("127.0.0.1:5757", "https://api.ipify.org", "test", "tset")
                .unwrap();
        let body = client.get().unwrap();
        let txt = String::from_utf8_lossy(&body);
        assert!(txt.contains(crate::tests::IP.as_str()));
    }

    #[test]
    fn client_socks_bad_auth() {
        let client =
            Client::connect_socks_auth("127.0.0.1:5757", "https://api.ipify.org", "test", "test");
        assert!(client.is_err());
    }
}

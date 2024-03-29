use std::io;
use std::net::SocketAddr;
use std::str::FromStr;

use url::{Host, Url};

use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct Addr {
    url: Url,
}

impl FromStr for Addr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut raw = String::from(s);
        if !raw.contains("://") {
            let mut is_secure = false;
            if raw.contains(':') {
                if let Some(host) = raw.clone().splitn(2, '/').nth(0) {
                    if let Some(port) = host.rsplitn(2, ':').nth(0) {
                        if port == "443" {
                            is_secure = true;
                        }
                    }
                }
            }
            if is_secure {
                raw.insert_str(0, "https://");
            } else {
                raw.insert_str(0, "http://");
            }
        }
        let url = Url::parse(&raw).map_err(Error::UrlParse)?;

        Ok(Addr { url })
    }
}

impl Addr {
    pub fn is_ssl(&self) -> bool {
        self.url.scheme() == "https"
    }

    pub fn addr_type(&self) -> Result<u8> {
        match self.url.host() {
            Some(Host::Ipv4(_)) => Ok(1u8),
            Some(Host::Ipv6(_)) => Ok(4u8),
            Some(Host::Domain(_)) => Ok(3u8),
            _ => Err(Error::InvalidHost),
        }
    }

    pub fn host(&self) -> Result<String> {
        match self.url.host() {
            Some(Host::Ipv4(ipv4)) => Ok(ipv4.to_string()),
            Some(Host::Ipv6(ipv6)) => Ok(ipv6.to_string()),
            Some(Host::Domain(domain)) => Ok(domain.to_string()),
            None => Err(Error::InvalidHost),
        }
    }

    pub fn host_vec(&self) -> Result<Vec<u8>> {
        match self.url.host() {
            Some(Host::Ipv4(ipv4)) => Ok(ipv4.octets().to_vec()),
            Some(Host::Ipv6(ipv6)) => Ok(ipv6.octets().to_vec()),
            Some(Host::Domain(domain)) => Ok(domain.as_bytes().to_vec()),
            None => Err(Error::InvalidHost),
        }
    }

    pub fn port(&self) -> Vec<u8> {
        match self.url.port_or_known_default() {
            Some(port) => vec![((port >> 8) & 0xff) as u8, (port & 0xff) as u8],
            None => vec![0u8, 80u8],
        }
    }

    pub fn to_vec(&self) -> io::Result<Vec<u8>> {
        let mut vec = Vec::new();
        vec.push(self.addr_type()?);
        match self.url.host() {
            Some(Host::Ipv4(_)) => vec.append(&mut self.host_vec()?),
            Some(Host::Ipv6(_)) => vec.append(&mut self.host_vec()?),
            Some(Host::Domain(_)) => {
                let mut addr = self.host_vec()?;
                vec.push(addr.len() as u8);
                vec.append(&mut addr);
            }
            None => (),
        }
        vec.append(&mut self.port());
        Ok(vec)
    }

    pub fn path(&self) -> String {
        self.url.path().to_string()
    }

    pub fn socket_addr(&self) -> Result<SocketAddr> {
        let socket_addrs = self.socket_addrs()?;
        if !socket_addrs.is_empty() {
            Ok(socket_addrs[0])
        } else {
            Err(Error::EmptyVec)
        }
    }

    pub fn socket_addrs(&self) -> Result<Vec<SocketAddr>> {
        self.url
            .socket_addrs(|| self.url.port_or_known_default())
            .map_err(Error::Io)
    }
}

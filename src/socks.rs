use native_tls::{TlsConnector, TlsStream};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpStream};
use std::str::FromStr;
use url::{Url, Host};
use crate::errors::Error;

#[derive(Debug, Clone)]
struct Addr {
    url: Url,
}

impl FromStr for Addr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
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
        let url =
            Url::parse(&raw).map_err(|e| Error::UrlParse(e))?;

        Ok(Addr { url })
    }
}

impl Addr {
    fn is_ssl(&self) -> bool {
        self.url.scheme() == "https"
    }

    fn addr_type(&self) -> Result<u8, Error> {
        match self.url.host() {
            Some(Host::Ipv4(_)) => Ok(1u8),
            Some(Host::Ipv6(_)) => Ok(4u8),
            Some(Host::Domain(_)) => Ok(3u8),
            _ => Err(Error::InvalidHost),
        }
    }

    fn host(&self) -> Result<String, Error> {
        match self.url.host() {
            Some(Host::Ipv4(ipv4)) => Ok(ipv4.to_string()),
            Some(Host::Ipv6(ipv6)) => Ok(ipv6.to_string()),
            Some(Host::Domain(domain)) => Ok(domain.to_string()),
            None => Err(Error::InvalidHost),
        }
    }

    fn host_vec(&self) -> Result<Vec<u8>, Error> {
        match self.url.host() {
            Some(Host::Ipv4(ipv4)) => Ok(ipv4.octets().to_vec()),
            Some(Host::Ipv6(ipv6)) => Ok(ipv6.octets().to_vec()),
            Some(Host::Domain(domain)) => Ok(domain.as_bytes().to_vec()),
            None => Err(Error::InvalidHost),
        }
    }

    fn port(&self) -> Vec<u8> {
        match self.url.port_or_known_default() {
            Some(port) => vec![((port >> 8) & 0xff) as u8, (port & 0xff) as u8],
            None => vec![0u8, 80u8],
        }
    }

    fn to_vec(&self) -> io::Result<Vec<u8>> {
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

    fn path(&self) -> String {
        self.url.path().to_string()
    }
}

#[derive(Clone, Copy)]
enum AuthMethod {
    NoAuth = 0,
    Plain = 2,
}

struct SocksAuth {
    method: AuthMethod,
    username: Vec<u8>,
    password: Vec<u8>,
}

impl SocksAuth {
    pub fn new_plain(username: &str, password: &str) -> Self {
        SocksAuth {
            method: AuthMethod::Plain,
            username: username.as_bytes().to_vec(),
            password: password.as_bytes().to_vec(),
        }
    }

    pub fn new() -> Self {
        SocksAuth {
            method: AuthMethod::NoAuth,
            username: Vec::new(),
            password: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub enum Stream {
    Tcp(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

#[derive(Debug)]
pub struct SocksStream {
    stream: Stream,
    target: Addr,
    bind_addr: Host,
    bind_port: [u8; 2],
}

impl SocksStream {
    pub fn connect(proxy: &str, target: &str) -> Result<SocksStream, Error> {
        Self::handshake(proxy, &target.parse()?, &SocksAuth::new())
    }

    pub fn connect_plain(
        proxy: &str,
        target: &str,
        username: &str,
        password: &str,
    ) -> Result<SocksStream, Error> {
        Self::handshake(
            proxy,
            &target.parse()?,
            &SocksAuth::new_plain(username, password),
        )
    }

    fn handshake(proxy: &str, target: &Addr, auth: &SocksAuth) -> Result<SocksStream, Error> {
        let mut socket = TcpStream::connect(proxy)?;
        // The initial greeting from the client
        //      field 1: SOCKS version, 1 byte (0x05 for this version)
        //      field 2: number of authentication methods supported, 1 byte
        //      field 3: authentication methods, variable length, 1 byte per method supported
        socket.write_all(&[5u8, 1u8, auth.method as u8])?;
        // The server's choice is communicated:
        //      field 1: SOCKS version, 1 byte (0x05 for this version)
        //      field 2: chosen authentication method, 1 byte, or 0xFF if no acceptable methods were offered
        let mut buf = [0u8; 2];
        socket.read_exact(&mut buf)?;
        match (buf[0] == 5u8, buf[1] == auth.method as u8) {
            (false, _) => Err(Error::InvalidServerVersion),
            (_, false) => Err(Error::InvalidAuthMethod),
            _ => Ok(())
        }?;
        if buf[1] == 2u8 {
            // For username/password authentication the client's authentication request is
            //     field 1: version number, 1 byte (0x01 for current version of username/password authentication)
            let mut packet = vec![1u8];
            //     field 2: username length, 1 byte
            packet.push(auth.username.len() as u8);
            //     field 3: username, 1–255 bytes
            packet.append(&mut auth.username.clone());
            //     field 4: password length, 1 byte
            packet.push(auth.password.len() as u8);
            //     field 5: password, 1–255 bytes
            packet.append(&mut auth.password.clone());
            socket.write_all(&packet)?;
            let mut buf = [0u8; 2];
            socket.read_exact(&mut buf)?;
            // Server response for username/password authentication:
            //     field 1: version, 1 byte (0x01 for current version of username/password authentication)
            //     field 2: status code, 1 byte
            //         0x00: success
            //         any other value is a failure, connection must be closed
            match (buf[0] != 1u8, buf[1] != 0u8) {
                (true, _) => Err(Error::InvalidAuthVersion),
                (_, true) => Err(Error::NotClosedConnection),
                _ => Ok(())
            }?;
        }
        let mut packet = Vec::new();
        // The client's connection request is
        //     field 1: SOCKS version number, 1 byte (0x05 for this version)
        packet.push(5u8);
        //     field 2: command code, 1 byte:
        //         0x01: establish a TCP/IP stream connection
        //         0x02: establish a TCP/IP port binding
        //         0x03: associate a UDP port
        packet.push(1u8);
        //     field 3: reserved, must be 0x00, 1 byte
        packet.push(0u8);
        //     field 4: address type, 1 byte:
        //         0x01: IPv4 address
        //         0x03: Domain name
        //         0x04: IPv6 address
        //     field 5: destination address of
        //         4 bytes for IPv4 address
        //         1 byte of name length followed by 1–255 bytes the domain name
        //         16 bytes for IPv6 address
        //     field 6: port number in a network byte order, 2 bytes
        packet.append(&mut target.to_vec()?);
        socket.write_all(&packet)?;
        let mut buf = [0u8; 4];
        socket.read_exact(&mut buf)?;
        // Server response:
        //     field 1: SOCKS protocol version, 1 byte (0x05 for this version)
        if buf[0] != 5u8 {
            return Err(Error::InvalidServerVersion);
        }
        //     field 2: status, 1 byte:
        //         0x00: request granted
        //         0x01: general failure
        //         0x02: connection not allowed by ruleset
        //         0x03: network unreachable
        //         0x04: host unreachable
        //         0x05: connection refused by destination host
        //         0x06: TTL expired
        //         0x07: command not supported / protocol error
        //         0x08: address type not supported
        match buf[1] {
            0 => Ok(()),
            1 => Err(Error::GeneralFailure),
            2 => Err(Error::InvalidRuleset),
            3 => Err(Error::NetworkUnreachable),
            4 => Err(Error::HostUnreachable),
            5 => Err(Error::RefusedByHost),
            6 => Err(Error::TtlExpired),
            7 => Err(Error::InvalidCommandProtocol),
            8 => Err(Error::InvalidAddressType),
            _ => Err(Error::UnknownError),
        }?;
        //     field 3: reserved, must be 0x00, 1 byte
        if buf[2] != 0u8 {
            return Err(Error::InvalidReservedByte);
        }
        //     field 4: address type, 1 byte:
        //         0x01: IPv4 address
        //         0x03: Domain name
        //         0x04: IPv6 address
        //     field 5: server bound address of
        //         4 bytes for IPv4 address
        //         1 byte of name length followed by 1–255 bytes the domain name
        //         16 bytes for IPv6 address
        let bind_addr = match buf[3] {
            1 => {
                let mut buf = [0u8; 4];
                socket.read_exact(&mut buf)?;
                Ok(Host::Ipv4(Ipv4Addr::from(buf)))
            }
            3 => {
                let mut len = [0u8; 1];
                socket.read_exact(&mut len)?;
                let mut buf = vec![0u8; len[0] as usize];
                socket.read_exact(&mut buf)?;
                Ok(Host::Domain(String::from_utf8_lossy(&buf).into_owned()))
            }
            4 => {
                let mut buf = [0u8; 16];
                socket.read_exact(&mut buf)?;
                Ok(Host::Ipv6(Ipv6Addr::from(buf)))
            }
            _ => Err(Error::InvalidAddressType),
        }?;
        let mut bind_port = [0u8; 2];
        //     field 6: server bound port number in a network byte order, 2 bytes
        socket.read_exact(&mut bind_port)?;
        let stream = if target.is_ssl() {
            let builder =
                TlsConnector::new().map_err(|e| Error::TlsConnector(e))?;
            Stream::Tls(Box::new(
                builder
                    .connect(&target.host()?, socket)
                    .map_err(|e| Error::NativeTls(e))?,
            ))
        } else {
            Stream::Tcp(socket)
        };
        // let stream = Stream::Tcp(socket);

        Ok(SocksStream {
            stream,
            target: target.clone(),
            bind_addr,
            bind_port
        })
    }
}

pub fn get(proxy: &str, target: &str) -> io::Result<Vec<u8>> {
    let mut stream = SocksStream::connect(proxy, target)?;
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\n\r\n",
        stream.target.path(),
        stream.target.host()?
    )
    .into_bytes();
    stream.write_all(&request)?;
    let mut response = vec![];
    stream.read_to_end(&mut response)?;
    let pos = response
        .windows(4)
        .position(|x| x == b"\r\n\r\n")
        .ok_or_else(|| Error::WrongHttp)?;
    let body = &response[pos + 4..response.len()];
    Ok(body.to_vec())
}

pub fn post_json(proxy: &str, target: &str, body: &str) -> io::Result<Vec<u8>> {
    let mut stream = SocksStream::connect(proxy, target)?;
    let body = if !body.is_empty() {
        format!("Content-Length: {}\r\n\r\n{}", body.len(), body)
    } else {
        String::new()
    };
    let request = format!(
        "POST {} HTTP/1.0\r\nHost: {}\r\nContent-Type: application/json\r\n{}\r\n",
        stream.target.path(),
        stream.target.host()?,
        body
    )
    .into_bytes();
    stream.write_all(&request)?;
    let mut response = vec![];
    stream.read_to_end(&mut response)?;
    let pos = response
        .windows(4)
        .position(|x| x == b"\r\n\r\n")
        .ok_or_else(|| Error::WrongHttp)?;
    let body = &response[pos + 4..response.len()];
    Ok(body.to_vec())
}

impl Read for SocksStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for SocksStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(stream) => stream.read(buf),
            Stream::Tls(stream) => (*stream).read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(stream) => stream.write(buf),
            Stream::Tls(stream) => (*stream).write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Tcp(stream) => stream.flush(),
            Stream::Tls(stream) => (*stream).flush(),
        }
    }
}

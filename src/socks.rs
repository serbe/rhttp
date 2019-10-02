// #![allow(dead_code)]
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpStream};

use url::Host;

use crate::addr::Addr;
use crate::errors::HttpError;
use crate::stream::Stream;

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

fn initial_greeting(socket: &mut TcpStream, auth: &SocksAuth) -> io::Result<()> {
    // The initial greeting from the client
    //      field 1: SOCKS version, 1 byte (0x05 for this version)
    //      field 2: number of authentication methods supported, 1 byte
    //      field 3: authentication methods, variable length, 1 byte per method supported
    socket.write_all(&[5u8, 1u8, auth.method as u8])
}

fn choise_communicated(socket: &mut TcpStream) -> Result<[u8; 2], HttpError> {
    // The server's choice is communicated:
    //      field 1: SOCKS version, 1 byte (0x05 for this version)
    //      field 2: chosen authentication method, 1 byte, or 0xFF if no acceptable methods were offered
    let mut buf = [0u8; 2];
    socket.read_exact(&mut buf)?;
    Ok(buf)
}

fn is_valid_socks_version(value: u8) -> Result<(), HttpError> {
    match value {
        5u8 => Ok(()),
        _ => Err(HttpError::InvalidServerVersion),
    }
}

fn try_auth(socket: &mut TcpStream, value: u8, auth: &SocksAuth) -> Result<(), HttpError> {
    if value == auth.method as u8 && value == 2u8 {
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
            (true, _) => Err(HttpError::InvalidAuthVersion),
            (_, true) => Err(HttpError::AuthFailure),
            _ => Ok(()),
        }
    } else if value == auth.method as u8 {
        Ok(())
    } else {
        Err(HttpError::InvalidAuthMethod)
    }
}

fn request_connection(socket: &mut TcpStream, target: Vec<u8>) -> io::Result<()> {
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
    packet.append(&mut target.clone());
    socket.write_all(&packet)
}

fn get_server_reponse(socket: &mut TcpStream) -> Result<(), HttpError> {
    let mut buf = [0u8; 3];
    socket.read_exact(&mut buf)?;
    // Server response:
    //     field 1: SOCKS protocol version, 1 byte (0x05 for this version)
    is_valid_socks_version(buf[0])?;
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
        1 => Err(HttpError::GeneralFailure),
        2 => Err(HttpError::InvalidRuleset),
        3 => Err(HttpError::NetworkUnreachable),
        4 => Err(HttpError::HostUnreachable),
        5 => Err(HttpError::RefusedByHost),
        6 => Err(HttpError::TtlExpired),
        7 => Err(HttpError::InvalidCommandProtocol),
        8 => Err(HttpError::InvalidAddressType),
        _ => Err(HttpError::UnknownError),
    }?;
    //     field 3: reserved, must be 0x00, 1 byte
    if buf[2] != 0u8 {
        Err(HttpError::InvalidReservedByte)
    } else {
        Ok(())
    }
}

fn get_host(socket: &mut TcpStream) -> Result<Host, HttpError> {
    let mut buf = [0u8; 1];
    //     field 4: address type, 1 byte:
    //         0x01: IPv4 address
    //         0x03: Domain name
    //         0x04: IPv6 address
    //     field 5: server bound address of
    //         4 bytes for IPv4 address
    //         1 byte of name length followed by 1–255 bytes the domain name
    //         16 bytes for IPv6 address
    socket.read_exact(&mut buf)?;
    match buf[0] {
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
        _ => Err(HttpError::InvalidAddressType),
    }
}

fn get_port(socket: &mut TcpStream) -> Result<[u8; 2], HttpError> {
    let mut bind_port = [0u8; 2];
    //     field 6: server bound port number in a network byte order, 2 bytes
    socket.read_exact(&mut bind_port)?;
    Ok(bind_port)
}

#[derive(Debug)]
pub struct SocksStream {
    stream: Stream,
    target: Addr,
    // bind_addr: Host,
    // bind_port: [u8; 2],
}

impl SocksStream {
    pub fn connect(proxy: &str, target: &str) -> Result<SocksStream, HttpError> {
        Self::handshake(proxy, &target.parse()?, &SocksAuth::new())
    }

    pub fn connect_plain(
        proxy: &str,
        target: &str,
        username: &str,
        password: &str,
    ) -> Result<SocksStream, HttpError> {
        Self::handshake(
            proxy,
            &target.parse()?,
            &SocksAuth::new_plain(username, password),
        )
    }

    fn handshake(proxy: &str, target: &Addr, auth: &SocksAuth) -> Result<SocksStream, HttpError> {
        let proxy_addr: Addr = proxy.parse()?;
        let mut socket = TcpStream::connect(proxy_addr.socket_addr()?)?;
        initial_greeting(&mut socket, auth)?;
        let buf = choise_communicated(&mut socket)?;
        is_valid_socks_version(buf[0])?;
        try_auth(&mut socket, buf[1], auth)?;
        request_connection(&mut socket, target.to_vec()?)?;
        get_server_reponse(&mut socket)?;
        let _host = get_host(&mut socket)?;
        let _port = get_port(&mut socket)?;
        let stream = if target.is_ssl() {
            Stream::new_tls(&target.host()?, socket)?
        } else {
            Stream::new_tcp(socket)
        };

        Ok(SocksStream {
            stream,
            target: target.clone(),
            // bind_addr,
            // bind_port,
        })
    }

    // fn get_stream(&self) -> io::Result<TcpStream> {
    //     let mut stream = match self.stream {
    //         Stream::Tcp(stream) => stream.try_clone()?,
    //         Stream::Tls(stream) => *stream,
    //     };
    //     Ok(stream)
    // }

    pub fn get(&mut self) -> io::Result<Vec<u8>> {
        // let mut stream = self.get_stream?;
        let request = format!(
            "GET {} HTTP/1.0\r\nHost: {}\r\n\r\n",
            self.target.path(),
            self.target.host()?
        )
        .into_bytes();
        self.stream.write_all(&request)?;
        self.stream.flush()?;
        let mut response = vec![];
        self.stream.read_to_end(&mut response)?;
        let pos = response
            .windows(4)
            .position(|x| x == b"\r\n\r\n")
            .ok_or_else(|| HttpError::WrongHttp)?;
        let body = &response[pos + 4..response.len()];
        Ok(body.to_vec())
    }

    pub fn post_json(&mut self, body: &str) -> io::Result<Vec<u8>> {
        let body = if !body.is_empty() {
            format!("Content-Length: {}\r\n\r\n{}", body.len(), body)
        } else {
            String::new()
        };
        let request = format!(
            "POST {} HTTP/1.0\r\nHost: {}\r\nContent-Type: application/json\r\n{}\r\n",
            self.target.path(),
            self.target.host()?,
            body
        )
        .into_bytes();
        self.stream.write_all(&request)?;
        self.stream.flush()?;
        let mut response = vec![];
        self.stream.read_to_end(&mut response)?;
        let pos = response
            .windows(4)
            .position(|x| x == b"\r\n\r\n")
            .ok_or_else(|| HttpError::WrongHttp)?;
        let body = &response[pos + 4..response.len()];
        Ok(body.to_vec())
    }
}

// pub fn get(proxy: &str, target: &str) -> io::Result<Vec<u8>> {
//     let mut stream = SocksStream::connect(proxy, target)?;
//     let request = format!(
//         "GET {} HTTP/1.0\r\nHost: {}\r\n\r\n",
//         stream.target.path(),
//         stream.target.host()?
//     )
//     .into_bytes();
//     stream.write_all(&request)?;
//     stream.flush()?;
//     let mut response = vec![];
//     stream.read_to_end(&mut response)?;
//     let pos = response
//         .windows(4)
//         .position(|x| x == b"\r\n\r\n")
//         .ok_or_else(|| HttpError::WrongHttp)?;
//     let body = &response[pos + 4..response.len()];
//     Ok(body.to_vec())
// }

// pub fn post_json(proxy: &str, target: &str, body: &str) -> io::Result<Vec<u8>> {
//     let mut stream = SocksStream::connect(proxy, target)?;
//     let body = if !body.is_empty() {
//         format!("Content-Length: {}\r\n\r\n{}", body.len(), body)
//     } else {
//         String::new()
//     };
//     let request = format!(
//         "POST {} HTTP/1.0\r\nHost: {}\r\nContent-Type: application/json\r\n{}\r\n",
//         stream.target.path(),
//         stream.target.host()?,
//         body
//     )
//     .into_bytes();
//     stream.write_all(&request)?;
//     stream.flush()?;
//     let mut response = vec![];
//     stream.read_to_end(&mut response)?;
//     let pos = response
//         .windows(4)
//         .position(|x| x == b"\r\n\r\n")
//         .ok_or_else(|| HttpError::WrongHttp)?;
//     let body = &response[pos + 4..response.len()];
//     Ok(body.to_vec())
// }

// impl Read for SocksStream {
//     fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
//         self.stream.read(buf)
//     }
// }

// impl Write for SocksStream {
//     fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
//         self.stream.write(buf)
//     }

//     fn flush(&mut self) -> io::Result<()> {
//         self.stream.flush()
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks() {
        let mut client = SocksStream::connect("127.0.0.1:5959", "https://api.ipify.org").unwrap();
        let body = client.get().unwrap();
        let txt = String::from_utf8_lossy(&body);
        assert!(txt.contains("92.50.223.31"));
    }

    #[test]
    fn socks_auth() {
        let mut client =
            SocksStream::connect_plain("127.0.0.1:5757", "https://api.ipify.org", "test", "tset")
                .unwrap();
        let body = client.get().unwrap();
        let txt = String::from_utf8_lossy(&body);
        assert!(txt.contains("92.50.223.31"));
    }

    #[test]
    fn socks_bad_auth() {
        let client =
            SocksStream::connect_plain("127.0.0.1:5757", "https://api.ipify.org", "test", "test");
        assert!(client.is_err());
    }
}

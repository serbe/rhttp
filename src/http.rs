use std::net::{Ipv4Addr, Ipv6Addr, TcpStream};
use std::io::{self, Read, Write};

use native_tls::{TlsConnector, TlsStream};
use url::{Host};

use crate::addr::Addr;
use crate::errors::HttpError;

#[derive(Debug)]
enum Stream {
    Tcp(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

pub struct HttpStream {
    stream: Stream,
    target: Addr,
    is_proxy: bool,
    // bind_addr: Host,
    // bind_port: [u8; 2],
}

impl HttpStream {
    pub fn connect(target: &str) -> Result<Self, HttpError> {
        let addr: Addr = target.parse()?;
        let stream = TcpStream::connect(addr.socket_addr()?)?;
        if addr.is_ssl() {
            let builder = TlsConnector::new().map_err(HttpError::TlsConnector)?;
            let tls_stream = Stream::Tls(Box::new(
                builder
                    .connect(&addr.host()?, stream)
                    .map_err(HttpError::NativeTls)?,
            ));
            Ok(HttpStream{
                stream: tls_stream,
                target: addr,
                is_proxy: false,
            })
            
        } else {
            Ok(HttpStream{
                stream: Stream::Tcp(stream),
                target: addr,
                is_proxy: false,
            })
        }
    }

    pub fn connect_proxy(proxy: &str, target: &str) -> Result<Self, HttpError> {
        let addr: Addr = target.parse()?;
        let proxy_addr: Addr = proxy.parse()?;
        let stream = TcpStream::connect(proxy_addr.socket_addr()?)?;
        if proxy_addr.is_ssl() {
            let builder = TlsConnector::new().map_err(HttpError::TlsConnector)?;
            let tls_stream = Stream::Tls(Box::new(
                builder
                    .connect(&proxy_addr.host()?, stream)
                    .map_err(HttpError::NativeTls)?,
            ));
            Ok(HttpStream{
                stream: tls_stream,
                target: addr,
                is_proxy: true,
            })
            
        } else {
            Ok(HttpStream{
                stream: Stream::Tcp(stream),
                target: addr,
                is_proxy: true,
            })
        }
    }

    pub fn get(&mut self) -> io::Result<Vec<u8>> {
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

impl Read for HttpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for HttpStream {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http() {
        let mut client =
            HttpStream::connect("https://api.ipify.org").unwrap();
        let body = client.get().unwrap();
        let txt = String::from_utf8_lossy(&body);
        assert!(txt.contains("5.138.250.78"));
    }

    #[test]
    fn http_proxy() {
        let mut client =
            HttpStream::connect_proxy("127.0.0.1:5858", "https://api.ipify.org").unwrap();
        let body = client.get().unwrap();
        let txt = String::from_utf8_lossy(&body);
        assert!(txt.contains("5.138.250.78"));
    }
}
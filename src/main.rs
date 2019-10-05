// use std::io::{Read, Write};
// use std::net::TcpStream;

use crate::error::Result;
// use crate::http::HttpStream;

mod error;

fn main() -> Result<()> {
    // let mut stream = TcpStream::connect("127.0.0.1:8888")?;

    // stream.write_all(b"CONNECT http://5.39.102.29:16016/c HTTP/1.0\r\n\r\n");

    // let mut buf = Vec::new();

    // stream.read_to_end(&mut buf);

    // println!("{}", String::from_utf8_lossy(&buf));

    Ok(())
}

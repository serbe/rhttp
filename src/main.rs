use std::io::{Read, Write};
use std::net::TcpStream;

fn my_ip() -> String {
    let mut stream = TcpStream::connect("api.ipify.org:80").unwrap();
    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n")
        .unwrap();
    stream.flush().unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).unwrap();
    let body = String::from_utf8(buf).unwrap();
    let split: Vec<&str> = body.splitn(2, "\r\n\r\n").collect();
    split[1].to_string()
}

// #[cfg(test)]
// mod tests {
//     lazy_static! {
//         pub static ref IP: String = crate::my_ip();
//     }

fn main() {
    // let mut stream = TcpStream::connect("127.0.0.1:8888")?;

    // stream.write_all(b"CONNECT http://5.39.102.29:16016/c HTTP/1.0\r\n\r\n");

    // let mut buf = Vec::new();

    // stream.read_to_end(&mut buf);

    // println!("{}", String::from_utf8_lossy(&buf));

    println!("{}", my_ip());
}

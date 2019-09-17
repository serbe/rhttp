// use std::io::Read;
// use std::io::Write;
// use std::net::TcpStream;

mod errors;
mod http;
// mod request;
// mod url;
mod socks;

// fn get_ip() {
//     let mut stream = TcpStream::connect("api.ipify.org:80").unwrap();
//     let request = "GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n".as_bytes();
//     stream.write_all(&request).unwrap();
//     stream.flush().unwrap();
//     let mut response = vec![];
//     stream.read_to_end(&mut response).unwrap();
//     stream.flush().unwrap();
//     let pos = response.windows(4).position(|x| x == b"\r\n\r\n").unwrap();
//     let body = &response[pos + 4..response.len()];
//     println!("{:?}", String::from_utf8(body.to_vec()));
// }

fn main() {
    
}

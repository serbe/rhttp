pub mod errors;
pub mod request;
pub mod url;

fn main() {
    let s = url::Url::from("http://www.google.com/?q=go+language").unwrap();
    println!("{:?}", s);
}

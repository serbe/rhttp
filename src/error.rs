use failure::Fail;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "{}", _0)]
    Io(#[cause] std::io::Error),
    #[fail(display = "{}", _0)]
    UrlParse(#[cause] url::ParseError),
    #[fail(display = "Invalid address host type")]
    InvalidHost,
    #[fail(display = "Invalid server version")]
    InvalidServerVersion,
    #[fail(display = "Auth method not supported")]
    InvalidAuthMethod,
    #[fail(display = "Invalid auth version")]
    InvalidAuthVersion,
    #[fail(display = "Failure, connection must be closed")]
    AuthFailure,
    #[fail(display = "Wrong http")]
    WrongHttp,
    #[fail(display = "{}", _0)]
    NativeTls(#[cause] native_tls::HandshakeError<std::net::TcpStream>),
    #[fail(display = "{}", _0)]
    TlsConnector(#[cause] native_tls::Error),
    #[fail(display = "Invalid address type")]
    InvalidAddressType,
    #[fail(display = "Invalid reserved byte")]
    InvalidReservedByte,
    #[fail(display = "Unknown error")]
    UnknownError,
    #[fail(display = "Command not supported / protocol error")]
    InvalidCommandProtocol,
    #[fail(display = "TTL expired")]
    TtlExpired,
    #[fail(display = "Connection refused by destination host")]
    RefusedByHost,
    #[fail(display = "Host unreachable")]
    HostUnreachable,
    #[fail(display = "Network unreachable")]
    NetworkUnreachable,
    #[fail(display = "Connection not allowed by ruleset")]
    InvalidRuleset,
    #[fail(display = "General failure")]
    GeneralFailure,
    // #[fail(display = "Target address is invalid: {}", _0)]
    // InvalidTargetAddress(&'static str),
    #[fail(display = "Url: is empty")]
    Empty(),
    #[fail(display = "Url: error get part from {}", _0)]
    GetPart(&'static str),
    #[fail(display = "Url: first path segment in URL cannot contain colon {}", _0)]
    NotContainColon(&'static str),
    #[fail(display = "Url: first path segment in {} cannot contain colon", _0)]
    FirstSegmentContainColon(&'static str),
    #[fail(display = "Url: missing protocol scheme {}", _0)]
    MissingScheme(&'static str),
    #[fail(display = "Url: invalid control character in {}", _0)]
    ContainsCTLByte(&'static str),
    #[fail(display = "Url: fragment is invalid {}", _0)]
    ParseFragment(&'static str),
    #[fail(display = "Url host is invalid: {}", _0)]
    ParseHost(&'static str),
    #[fail(display = "Url IPv6 is invalid: {}", _0)]
    ParseIPv6(&'static str),
    #[fail(display = "Url path is invalid: {}", _0)]
    ParsePath(&'static str),
    #[fail(display = "Url port is invalid: {}", _0)]
    ParsePort(&'static str),
    #[fail(display = "Url query is invalid: {}", _0)]
    ParseQuery(&'static str),
    #[fail(display = "Url scheme is invalid: {}", _0)]
    ParseScheme(&'static str),
    #[fail(display = "Url UserInfo is invalid: {}", _0)]
    ParseUserInfo(&'static str),
    #[fail(display = "General SOCKS server failure: {}", _0)]
    ReplyGeneralFailure(&'static str),
    #[fail(display = "Connection not allowed by ruleset: {}", _0)]
    ReplyConnectionNotAllowed(&'static str),
    #[fail(display = "Network unreachable: {}", _0)]
    ReplyNetworkUnreachable(&'static str),
    #[fail(display = "Host unreachable: {}", _0)]
    ReplyHostUnreachable(&'static str),
    #[fail(display = "Connection refused: {}", _0)]
    ReplyConnectionRefused(&'static str),
    #[fail(display = "TTL expired: {}", _0)]
    ReplyTtlExpired(&'static str),
    #[fail(display = "Command not supported: {}", _0)]
    ReplyCommandNotSupported(&'static str),
    #[fail(display = "Address type not supported: {}", _0)]
    ReplyAddressTypeNotSupported(&'static str),
    #[fail(display = "Other reply: {} {}", _0, _1)]
    ReplyOtherReply(&'static str, u8),
    #[fail(display = "Empty vector")]
    EmptyVec,
    #[fail(display = "Unsupported proxy")]
    UnsupportedProxy,
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<String> for Error {
    fn from(err: String) -> Error {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            err.to_string(),
        ))
    }
}

impl From<&str> for Error {
    fn from(err: &str) -> Error {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            err.to_string(),
        ))
    }
}

impl From<Error> for std::io::Error {
    fn from(err: Error) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, err.to_string())
    }
}

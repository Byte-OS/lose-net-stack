#[derive(Debug)]
pub enum NetServerError {
    Unsupported,
    EmptyClient,
    EmptyData,
    NoUdpRemoteAddress,
    ServerNotExists,
    PortWasUsed,
    Blocking,
}

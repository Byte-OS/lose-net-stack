pub trait NetInterface {
    fn send(data: &[u8]);
}
extern crate pkcs7pad;

use pkcs7pad::unpad;

fn main() {
    assert_eq!(None, unpad(b"ICE ICE BABY\x05\x05\x05\x05"));
    assert_eq!(None, unpad(b"ICE ICE BABY\x01\x02\x03\x04"));

    let input = b"ICE ICE BABY\x04\x04\x04\x04";

    let unpadded = unpad(input).unwrap();

    println!("{}", String::from_utf8(unpadded).unwrap());
}

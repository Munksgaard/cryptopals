extern crate base64;
extern crate hexstr;

fn main() {
    let s: &[u8] = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

    let bytes = hexstr::parse(s);

    println!("String: {:?}", String::from_utf8(bytes.clone()).unwrap());

    let decoded = base64::encode(&bytes);

    println!("Encoded: {:?}", String::from_utf8(decoded).unwrap());
}

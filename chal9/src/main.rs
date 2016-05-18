extern crate pkcs7pad;
extern crate hexstr;

fn main() {
    let input = b"YELLOW SUBMARINE";

    let padded = pkcs7pad::pad(input, 20);

    hexstr::print_bytes(&padded);
}

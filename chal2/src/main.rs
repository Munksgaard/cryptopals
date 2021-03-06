extern crate hexstr;
extern crate xorcrypt;


fn main() {
    let right = hexstr::parse(b"1c0111001f010100061a024b53535009181c");
    let left = hexstr::parse(b"686974207468652062756c6c277320657965");

    let res = xorcrypt::xor(&left, &right);

    let expected = hexstr::parse(b"746865206b696420646f6e277420706c6179");

    assert_eq!(res, expected);

    hexstr::print_bytes(&res);
}

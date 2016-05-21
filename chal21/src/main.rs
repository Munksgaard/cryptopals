extern crate mersenne;

fn main() {
    let mut rng = mersenne::seed_mt(0);

    for _ in 0..100 {
        println!("{}", rng.extract_number());
    }
}

//! Dev helper: print `<status>\t<signer_name>\t<path>` for each path arg.

fn main() {
    for arg in std::env::args().skip(1) {
        let r = ingot_core::authenticode::check_signature(std::path::Path::new(&arg));
        println!("{}\t{}\t{arg}", r.status, r.signer_name);
    }
}

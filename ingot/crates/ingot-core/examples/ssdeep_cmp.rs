//! Dev helper: `ssdeep_cmp <hashA> <hashB>` prints `ingot-core`'s ported
//! ppdeep-compatible compare score, for diffing against ppdeep.compare.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    println!("{}", ingot_core::ssdeep::compare(&args[0], &args[1]));
}

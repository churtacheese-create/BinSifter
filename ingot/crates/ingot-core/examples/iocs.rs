//! Dev helper: read strings (one per line) from stdin, print
//! `<count>\t<display>` for `ingot-core`'s IOC extraction. For diffing
//! against `binsifter.core.iocs.extract_iocs`.

use std::io::Read;

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let lines: Vec<&str> = input.lines().collect();
    let r = ingot_core::iocs::extract_iocs(&lines);
    println!("{}\t{}", r.count, r.display);
}

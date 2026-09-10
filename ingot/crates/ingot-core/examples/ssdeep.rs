//! Dev helper: print `fuzzyhash` output for each path argument, one
//! `<hash>\t<path>` line, for diffing against ppdeep during Phase 4.

fn main() {
    for arg in std::env::args().skip(1) {
        match fuzzyhash::FuzzyHash::file(&arg) {
            Ok(h) => println!("{h}\t{arg}"),
            Err(e) => println!("ERR:{e}\t{arg}"),
        }
    }
}

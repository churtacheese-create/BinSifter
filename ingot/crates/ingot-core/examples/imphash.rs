//! Dev helper: print `ingot-core`'s imphash for each path argument, one
//! `<imphash-or-none>\t<path>` line per file. Used to diff against pefile's
//! `get_imphash()` during Phase 2 validation.

fn main() {
    for arg in std::env::args().skip(1) {
        let h = ingot_core::imphash::compute_imphash(std::path::Path::new(&arg))
            .unwrap_or_else(|| "none".to_string());
        println!("{h}\t{arg}");
    }
}

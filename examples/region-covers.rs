// Does any Arxan-declared encrypted region cover a given VA?
//
// This is the question that decides whether a MinHook detour can be silently overwritten: a
// stub that decrypts a region at runtime writes original bytes back over whatever is there,
// with no integrity check involved. `region-dump` cannot answer it, because it prints regions
// only AFTER apply_relocs_and_resolve_conflicts, which on DS2 eliminates every one of them on
// entropy grounds. Elimination is dearxan declining to PRE-APPLY a decryption it does not
// trust; it says nothing about what the stub does when it runs.
//
// So this reads si.encrypted_regions directly, before any resolution.
//
//   cargo run --release --example region-covers --no-default-features --features rayon -- <exe> 0x14014bec0
use std::path::PathBuf;

use dearxan::analysis::{StubAnalyzer, analyze_all_stubs_with};
use dearxan_test_utils::{FsExe, init_log};
use pelite::pe64::Pe;

fn main() {
    init_log(log::LevelFilter::Error);
    let in_path = std::env::args().nth(1).expect("usage: region-covers <exe> <va> [<va>...]");
    let targets: Vec<u64> = std::env::args()
        .skip(2)
        .map(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).expect("hex va"))
        .collect();
    assert!(!targets.is_empty(), "give at least one VA");

    let path = PathBuf::from(&in_path);
    let game = FsExe {
        game: path.file_stem().unwrap().to_string_lossy().to_string(),
        ver: "0".to_string(),
        path,
    };
    let mapped = game.load_64().expect("load");
    let pe = mapped.pe_view();
    let image_base = pe.optional_header().ImageBase;

    let stub_infos = analyze_all_stubs_with(pe, StubAnalyzer::new());

    let mut regions = 0usize;
    // Coverage is tracked PER TARGET. A single shared counter is wrong: with several VAs and only
    // one of them covered, every target would report the covered verdict. That bug shipped in the
    // first version of this file and was caught in review. It did not corrupt the DS2 numbers,
    // because none of the three VAs tested were covered and the counter stayed at zero for all of
    // them -- but "the bug did not fire this time" is not the same as "the tool is right".
    let mut covering = vec![0usize; targets.len()];
    let mut min_va = u64::MAX;
    let mut max_va = 0u64;
    for si in stub_infos.iter().filter_map(|si| si.as_ref().ok()) {
        let Some(rlist) = si.encrypted_regions.as_ref() else { continue };
        for r in rlist.regions.iter() {
            let start = image_base + r.rva as u64;
            let end = start + r.size as u64;
            regions += 1;
            min_va = min_va.min(start);
            max_va = max_va.max(end);
            for (i, t) in targets.iter().enumerate() {
                if (start..end).contains(t) {
                    covering[i] += 1;
                    println!(
                        "COVERED {t:#x} by region {start:#x}..{end:#x} ({} bytes), stub test_rsp={:#x}",
                        r.size, si.test_rsp_va
                    );
                }
            }
        }
    }
    println!("regions_examined={regions} span={min_va:#x}..{max_va:#x}");
    for (i, t) in targets.iter().enumerate() {
        let n = covering[i];
        if n > 0 {
            println!("{t:#x}: COVERED by {n} declared encrypted region(s) -- see above");
        } else {
            println!("{t:#x}: NOT covered by any declared encrypted region");
        }
    }
}

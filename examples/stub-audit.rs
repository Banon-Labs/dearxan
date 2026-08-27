// Audit Arxan stub analysis coverage: how many stubs analyze OK, how many error,
// how many OK stubs actually guard encrypted regions, and what the failure modes are.
// Usage: cargo run --release --example stub-audit --no-default-features --features rayon -- <exe>
use std::collections::BTreeMap;
use std::path::PathBuf;

use dearxan::analysis::{StubAnalyzer, analyze_all_stubs_with};
use dearxan_test_utils::{FsExe, init_log};

// Bucket an error message by blanking out hex-ish runs (addresses) so distinct
// instances of the same failure mode collapse into one key.
fn normalize(msg: &str) -> String {
    let mut out = String::new();
    let mut run = 0usize;
    for c in msg.chars() {
        if c.is_ascii_hexdigit() {
            run += 1;
        } else {
            if run >= 3 {
                out.push_str("<hex>");
            } else {
                for _ in 0..run {
                    out.push('0');
                }
            }
            run = 0;
            out.push(c);
        }
    }
    if run >= 3 {
        out.push_str("<hex>");
    }
    out
}

fn main() {
    init_log(log::LevelFilter::Error); // quiet the per-stub chatter
    let in_path = std::env::args().nth(1).expect("usage: stub-audit <exe>");
    let path = PathBuf::from(&in_path);
    let game = FsExe {
        game: path.file_stem().unwrap().to_string_lossy().to_string(),
        ver: "0".to_string(),
        path,
    };

    let mapped = game.load_64().expect("failed to load image");
    let pe = mapped.pe_view();

    let analyzer = StubAnalyzer::new();
    let infos = analyze_all_stubs_with(pe, analyzer);

    let total = infos.len();
    let (mut ok, mut err) = (0usize, 0usize);
    let (mut with_regions, mut without_regions) = (0usize, 0usize);
    let mut region_lists = 0usize;
    let mut err_kinds: BTreeMap<String, usize> = BTreeMap::new();
    let mut err_samples: Vec<String> = Vec::new();

    for r in &infos {
        match r {
            Ok(si) => {
                ok += 1;
                match &si.encrypted_regions {
                    Some(rl) => {
                        with_regions += 1;
                        region_lists += rl.len();
                    }
                    None => without_regions += 1,
                }
            }
            Err(e) => {
                err += 1;
                let msg = format!("{e}");
                *err_kinds.entry(normalize(&msg)).or_default() += 1;
                if err_samples.len() < 25 {
                    err_samples.push(msg);
                }
            }
        }
    }

    println!("== STUB AUDIT ==");
    println!("total_stubs             = {total}");
    println!("analyzed_ok             = {ok}");
    println!("analyze_error           = {err}");
    println!("ok_with_encrypted_regs  = {with_regions}");
    println!("ok_without_regs (inert) = {without_regions}");
    println!("total_region_lists      = {region_lists}");
    println!("\n== ERROR MODES (normalized -> count) ==");
    let mut kinds: Vec<_> = err_kinds.into_iter().collect();
    kinds.sort_by(|a, b| b.1.cmp(&a.1));
    for (k, v) in &kinds {
        println!("{v:5}  {k}");
    }
    println!("\n== SAMPLE RAW ERRORS ==");
    for s in &err_samples {
        println!("  {s}");
    }
}

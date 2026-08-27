// Dump each Arxan stub's control-flow info for trampoline resolution:
//   test_rsp_va, context_pop_va, return_gadget(addr,stack_off), has_encrypted_regions
// Usage: cargo run --release --example stub-cfg --no-default-features --features rayon -- <exe> <out.tsv>
use std::io::Write;
use std::path::PathBuf;
use dearxan::analysis::{StubAnalyzer, analyze_all_stubs_with};
use dearxan_test_utils::{FsExe, init_log};

fn main() {
    init_log(log::LevelFilter::Error);
    let inp = std::env::args().nth(1).expect("usage: stub-cfg <exe> <out>");
    let outp = std::env::args().nth(2).expect("usage: stub-cfg <exe> <out>");
    let path = PathBuf::from(&inp);
    let game = FsExe { game: path.file_stem().unwrap().to_string_lossy().to_string(), ver: "0".into(), path };
    let mapped = game.load_64().expect("load");
    let pe = mapped.pe_view();
    let infos = analyze_all_stubs_with(pe, StubAnalyzer::new());
    let mut out = std::fs::File::create(&outp).expect("create");
    writeln!(out, "test_rsp_va\tcontext_pop_va\treturn_gadget_va\tstack_off\thas_enc").unwrap();
    let mut n = 0;
    for si in infos.iter().filter_map(|r| r.as_ref().ok()) {
        let (rg, so) = match &si.return_gadget {
            Some(g) => (format!("{:x}", g.address), g.stack_offset as i64),
            None => ("none".to_string(), -1),
        };
        writeln!(out, "{:x}\t{:x}\t{}\t{}\t{}", si.test_rsp_va, si.context_pop_va, rg, so,
                 si.encrypted_regions.is_some()).unwrap();
        n += 1;
    }
    println!("wrote {n} stubs -> {outp}");
}

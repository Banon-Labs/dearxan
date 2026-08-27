// Dump every decrypted region dearxan applies: RVA, length, and the decrypted bytes'
// first-instruction sanity. Writes a TSV of (rva,len) for cross-referencing against a
// ground-truth runtime dump. Usage:
//   cargo run --release --example region-dump --no-default-features --features rayon -- <exe> <out.tsv>
use std::io::Write;
use std::path::PathBuf;

use dearxan::analysis::{StubAnalyzer, analyze_all_stubs_with, encryption};
use dearxan_test_utils::{FsExe, init_log};
use pelite::pe64::{Pe, PeObject};

fn main() {
    init_log(log::LevelFilter::Error);
    let in_path = std::env::args().nth(1).expect("usage: region-dump <exe> <out.tsv>");
    let out_path = std::env::args().nth(2).expect("usage: region-dump <exe> <out.tsv>");
    let path = PathBuf::from(&in_path);
    let game = FsExe {
        game: path.file_stem().unwrap().to_string_lossy().to_string(),
        ver: "0".to_string(),
        path,
    };
    let mapped = game.load_64().expect("load");
    let pe = mapped.pe_view();
    let image_base = pe.optional_header().ImageBase;

    let analyzer = StubAnalyzer::new();
    let stub_infos = analyze_all_stubs_with(pe, analyzer);
    let final_patches = encryption::apply_relocs_and_resolve_conflicts(
        stub_infos.iter().filter_map(|si| si.as_ref().ok()).filter_map(|si| si.encrypted_regions.as_ref()),
        pe,
        None,
    )
    .expect("resolve");

    // The mapped image BEFORE we overwrite = ciphertext at the encrypted RVAs.
    let cipher_image = pe.image();

    let mut out = std::fs::File::create(&out_path).expect("create tsv");
    // Binary before/after records: [rva u64][len u32][cipher len][plain len]
    let mut rec = std::fs::File::create(format!("{out_path}.rec")).expect("create rec");
    let mut n = 0usize;
    let mut bytes = 0usize;
    let mut min_va = u64::MAX;
    let mut max_va = 0u64;
    for rlist in &final_patches {
        for r in &rlist.regions {
            if let Some(b) = r.decrypted_slice(rlist) {
                let va = image_base + r.rva as u64;
                let rva = r.rva as usize;
                writeln!(out, "{:x}\t{}", va, b.len()).unwrap();
                if rva + b.len() <= cipher_image.len() {
                    rec.write_all(&va.to_le_bytes()).unwrap();
                    rec.write_all(&(b.len() as u32).to_le_bytes()).unwrap();
                    rec.write_all(&cipher_image[rva..rva + b.len()]).unwrap();
                    rec.write_all(b).unwrap();
                }
                n += 1;
                bytes += b.len();
                min_va = min_va.min(va);
                max_va = max_va.max(va + b.len() as u64);
            }
        }
    }
    println!("regions={n} bytes={bytes} va_range=0x{min_va:x}..0x{max_va:x}");
}

// Produce a DEOBFUSCATED (Arxan-decrypted) copy of a FromSoftware executable as a flat MAPPED
// image (file offset == RVA), for static analysis with objdump. Decrypts all Arxan-encrypted
// regions and writes them back over the mapped image. Usage:
//   cargo run --release --example deobfuscate --no-default-features --features rayon -- <exe> <out>
// The output is a memory image: VA = file_offset + image_base (0x140000000 for ER).
// NOTE: the output is the copyrighted game binary -- do NOT commit it.
use std::path::PathBuf;

use dearxan::analysis::{StubAnalyzer, analyze_all_stubs_with, encryption};
use dearxan_test_utils::{FsExe, init_log};
use pelite::pe64::{Pe, PeObject};

fn main() {
    init_log(log::LevelFilter::Info);

    let mut args = std::env::args().skip(1);
    let in_path = args.next().expect("usage: deobfuscate <exe> <out>");
    let out_path = args.next().expect("usage: deobfuscate <exe> <out>");

    let path = PathBuf::from(&in_path);
    let game = FsExe {
        game: path.file_stem().unwrap().to_string_lossy().to_string(),
        ver: "0".to_string(),
        path,
    };

    log::info!("loading {in_path}");
    let mapped = game.load_64().expect("failed to load the executable image");
    let pe = mapped.pe_view();
    let image_base = pe.optional_header().ImageBase;
    log::info!(
        "image_base = 0x{image_base:x}, mapped size = 0x{:x}",
        pe.image().len()
    );

    log::info!("analyzing all Arxan stubs (this can take a long time)...");
    let analyzer = StubAnalyzer::new();
    let stub_infos = analyze_all_stubs_with(pe, analyzer);
    let ok = stub_infos.iter().filter(|s| s.is_ok()).count();
    log::info!("found {} stubs ({ok} ok)", stub_infos.len());

    log::info!("resolving + decrypting encrypted regions...");
    let final_patches = encryption::apply_relocs_and_resolve_conflicts(
        stub_infos
            .iter()
            .filter_map(|si| si.as_ref().ok())
            .filter_map(|si| si.encrypted_regions.as_ref()),
        pe,
        None,
    )
    .expect("apply_relocs_and_resolve_conflicts failed");

    // Clone the mapped image and overwrite each decrypted region at its RVA.
    let mut image = pe.image().to_vec();
    let mut applied = 0usize;
    let mut bytes_written = 0usize;
    for rlist in &final_patches {
        for r in &rlist.regions {
            if let Some(bytes) = r.decrypted_slice(rlist) {
                let rva = r.rva as usize;
                let end = rva + bytes.len();
                if end <= image.len() {
                    image[rva..end].copy_from_slice(bytes);
                    applied += 1;
                    bytes_written += bytes.len();
                } else {
                    log::warn!(
                        "region rva=0x{rva:x} len=0x{:x} out of image bounds",
                        bytes.len()
                    );
                }
            }
        }
    }
    log::info!("applied {applied} decrypted regions, {bytes_written} bytes total");

    std::fs::write(&out_path, &image).expect("failed to write output");
    log::info!("wrote deobfuscated mapped image to {out_path} (VA = offset + 0x{image_base:x})");
}

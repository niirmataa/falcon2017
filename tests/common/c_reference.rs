use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use super::hex_to_bytes;

#[cfg(feature = "deterministic-tests")]
pub struct KeygenOutput {
    pub sk: Vec<u8>,
    pub pk: Vec<u8>,
}

#[cfg(feature = "deterministic-tests")]
pub fn keygen(logn: u32, seed: &[u8], comp: u32) -> KeygenOutput {
    let output = run_helper(&[
        "keygen",
        &logn.to_string(),
        &to_hex(seed),
        &comp.to_string(),
    ]);
    KeygenOutput {
        sk: parse_hex_field(&output, "SK"),
        pk: parse_hex_field(&output, "PK"),
    }
}

pub fn hash_to_point_binary(logn: u32, nonce: &[u8], msg: &[u8]) -> Vec<u16> {
    let output = run_helper(&[
        "hash_to_point_binary",
        &logn.to_string(),
        &to_hex(nonce),
        &to_hex(msg),
    ]);
    let packed = parse_string_field(&output, "C0");
    assert_eq!(
        packed.len() % 4,
        0,
        "packed c0 must be a multiple of four hex chars"
    );
    packed
        .as_bytes()
        .chunks_exact(4)
        .map(|chunk| {
            let text = std::str::from_utf8(chunk).expect("utf8 hex chunk");
            u16::from_str_radix(text, 16).expect("u16 hex")
        })
        .collect()
}

#[cfg(feature = "deterministic-tests")]
pub fn verify(pk: &[u8], nonce: &[u8], msg: &[u8], sig_body: &[u8]) -> i32 {
    let output = run_helper(&[
        "verify",
        &to_hex(pk),
        &to_hex(nonce),
        &to_hex(msg),
        &to_hex(sig_body),
    ]);
    parse_string_field(&output, "STATUS")
        .parse::<i32>()
        .expect("verify status")
}

fn run_helper(args: &[&str]) -> String {
    static HELPER: OnceLock<PathBuf> = OnceLock::new();
    let helper = HELPER.get_or_init(build_helper);
    let output = Command::new(&helper)
        .args(args)
        .output()
        .expect("run C reference helper");
    if !output.status.success() {
        panic!(
            "C reference helper failed: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    String::from_utf8(output.stdout).expect("utf8 helper output")
}

fn build_helper() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let build_dir = manifest_dir.join("target").join("c_reference");
    fs::create_dir_all(&build_dir).expect("create c_reference build dir");
    let helper_path = build_dir.join(format!("falcon_ref_helper-{}", std::process::id()));
    if helper_path.exists() {
        return helper_path;
    }
    let temp_path = build_dir.join(format!("falcon_ref_helper-{}.tmp", std::process::id()));

    let references = manifest_dir.join("references").join("falcon-2017-extra");
    let helper_src = manifest_dir
        .join("tests")
        .join("common")
        .join("falcon_ref_helper.c");
    let compile_status = Command::new("cc")
        .current_dir(&manifest_dir)
        .arg("-std=c99")
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-I")
        .arg(path_arg(&references))
        .arg(path_arg(&helper_src))
        .arg(path_arg(&references.join("falcon-enc.c")))
        .arg(path_arg(&references.join("falcon-keygen.c")))
        .arg(path_arg(&references.join("falcon-vrfy.c")))
        .arg(path_arg(&references.join("falcon-fft.c")))
        .arg(path_arg(&references.join("frng.c")))
        .arg(path_arg(&references.join("shake.c")))
        .arg("-lm")
        .arg("-o")
        .arg(path_arg(&temp_path))
        .status()
        .expect("compile C reference helper");
    assert!(
        compile_status.success(),
        "C reference helper compilation failed"
    );
    fs::rename(&temp_path, &helper_path).expect("publish C reference helper");
    helper_path
}

fn parse_hex_field(output: &str, key: &str) -> Vec<u8> {
    hex_to_bytes(&parse_string_field(output, key))
}

fn parse_string_field(output: &str, key: &str) -> String {
    let prefix = format!("{key}=");
    output
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(str::to_string)
        .unwrap_or_else(|| panic!("missing field {key} in helper output"))
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("hex formatting");
    }
    out
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

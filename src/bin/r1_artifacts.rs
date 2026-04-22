#[cfg(feature = "deterministic-tests")]
#[path = "../../tests/common/mod.rs"]
mod common;

#[cfg(feature = "deterministic-tests")]
use common::{c_reference, differential_bytes, FixedSeedRng};

#[cfg(feature = "deterministic-tests")]
use falcon2017::{Compression, Falcon1024, Falcon512, Nonce, PublicKey, SecretKey};
#[cfg(feature = "deterministic-tests")]
use sha2::{Digest, Sha256};

#[cfg(feature = "deterministic-tests")]
use std::fmt::Write as _;
#[cfg(feature = "deterministic-tests")]
use std::fs;
#[cfg(feature = "deterministic-tests")]
use std::path::{Path, PathBuf};

#[cfg(feature = "deterministic-tests")]
const DEFAULT_KEYGEN_CASES_PER_LOGN: u32 = 10_000;
#[cfg(feature = "deterministic-tests")]
const DEFAULT_SIGN_CASES_PER_LOGN: u32 = 1_000;
#[cfg(feature = "deterministic-tests")]
const KEYGEN_ARTIFACT_FILENAME: &str = "ref-differential-keygen.json";
#[cfg(feature = "deterministic-tests")]
const SIGN_ARTIFACT_FILENAME: &str = "ref-differential-sign.json";
#[cfg(feature = "deterministic-tests")]
const SUMMARY_ARTIFACT_FILENAME: &str = "ref-differential-summary.md";

#[cfg(not(feature = "deterministic-tests"))]
fn main() {
    eprintln!("r1_artifacts requires --features deterministic-tests");
    std::process::exit(2);
}

#[cfg(feature = "deterministic-tests")]
fn main() {
    if let Err(err) = run() {
        eprintln!("r1_artifacts: {err}");
        std::process::exit(1);
    }
}

#[cfg(feature = "deterministic-tests")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Generate,
    Check,
}

#[cfg(feature = "deterministic-tests")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum ArtifactKind {
    Keygen,
    Sign,
    Summary,
    All,
}

#[cfg(feature = "deterministic-tests")]
struct Options {
    mode: Mode,
    kind: ArtifactKind,
    out: Option<PathBuf>,
    out_dir: PathBuf,
    keygen_cases_per_logn: u32,
    sign_cases_per_logn: u32,
}

#[cfg(feature = "deterministic-tests")]
#[derive(Default, Clone, Copy)]
struct KeygenStats {
    total_cases: u32,
    pk_mismatches: u32,
    sk_mismatches: u32,
    derived_pk_mismatches: u32,
    decoded_pk_mismatches: u32,
    decoded_sk_mismatches: u32,
    decoded_derived_pk_mismatches: u32,
}

#[cfg(feature = "deterministic-tests")]
#[derive(Default, Clone, Copy)]
struct SignStats {
    total_cases: u32,
    key_pk_mismatches: u32,
    key_sk_mismatches: u32,
    nonce_mismatches: u32,
    sig_mismatches: u32,
    rust_verify_rust_failures: u32,
    rust_verify_c_failures: u32,
    c_verify_rust_failures: u32,
    c_verify_c_failures: u32,
}

#[cfg(feature = "deterministic-tests")]
fn run() -> Result<(), String> {
    let options = parse_options()?;
    match options.kind {
        ArtifactKind::All => run_all(&options),
        ArtifactKind::Keygen | ArtifactKind::Sign | ArtifactKind::Summary => run_one(&options),
    }
}

#[cfg(feature = "deterministic-tests")]
fn run_all(options: &Options) -> Result<(), String> {
    let (keygen_text, keygen_stats) = build_keygen_artifact(options.keygen_cases_per_logn)?;
    let (sign_text, sign_stats) = build_sign_artifact(options.sign_cases_per_logn)?;
    let summary_text = build_summary_artifact(
        options.keygen_cases_per_logn,
        options.sign_cases_per_logn,
        keygen_stats,
        sign_stats,
    );

    write_or_check(
        &options.out_dir.join(KEYGEN_ARTIFACT_FILENAME),
        &keygen_text,
        options.mode,
    )?;
    write_or_check(
        &options.out_dir.join(SIGN_ARTIFACT_FILENAME),
        &sign_text,
        options.mode,
    )?;
    write_or_check(
        &options.out_dir.join(SUMMARY_ARTIFACT_FILENAME),
        &summary_text,
        options.mode,
    )?;

    ensure_keygen_clean(keygen_stats)?;
    ensure_sign_clean(sign_stats)?;
    Ok(())
}

#[cfg(feature = "deterministic-tests")]
fn run_one(options: &Options) -> Result<(), String> {
    let path = resolve_output_path(options)?;
    match options.kind {
        ArtifactKind::Keygen => {
            let (text, stats) = build_keygen_artifact(options.keygen_cases_per_logn)?;
            write_or_check(&path, &text, options.mode)?;
            ensure_keygen_clean(stats)?;
        }
        ArtifactKind::Sign => {
            let (text, stats) = build_sign_artifact(options.sign_cases_per_logn)?;
            write_or_check(&path, &text, options.mode)?;
            ensure_sign_clean(stats)?;
        }
        ArtifactKind::Summary => {
            let (_, keygen_stats) = build_keygen_artifact(options.keygen_cases_per_logn)?;
            let (_, sign_stats) = build_sign_artifact(options.sign_cases_per_logn)?;
            let text = build_summary_artifact(
                options.keygen_cases_per_logn,
                options.sign_cases_per_logn,
                keygen_stats,
                sign_stats,
            );
            write_or_check(&path, &text, options.mode)?;
            ensure_keygen_clean(keygen_stats)?;
            ensure_sign_clean(sign_stats)?;
        }
        ArtifactKind::All => unreachable!(),
    }
    Ok(())
}

#[cfg(feature = "deterministic-tests")]
fn parse_options() -> Result<Options, String> {
    let mut args = std::env::args().skip(1);
    let command = args.next().ok_or_else(usage)?;
    let (mode, kind) = match command.as_str() {
        "all" => (Mode::Generate, ArtifactKind::All),
        "keygen" => (Mode::Generate, ArtifactKind::Keygen),
        "sign" => (Mode::Generate, ArtifactKind::Sign),
        "summary" => (Mode::Generate, ArtifactKind::Summary),
        "check-all" => (Mode::Check, ArtifactKind::All),
        "check-keygen" => (Mode::Check, ArtifactKind::Keygen),
        "check-sign" => (Mode::Check, ArtifactKind::Sign),
        "check-summary" => (Mode::Check, ArtifactKind::Summary),
        _ => return Err(usage()),
    };

    let mut out = None;
    let mut out_dir = PathBuf::from("artifacts");
    let mut keygen_cases_per_logn = DEFAULT_KEYGEN_CASES_PER_LOGN;
    let mut sign_cases_per_logn = DEFAULT_SIGN_CASES_PER_LOGN;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => {
                let value = args.next().ok_or_else(usage)?;
                out = Some(PathBuf::from(value));
            }
            "--out-dir" => {
                let value = args.next().ok_or_else(usage)?;
                out_dir = PathBuf::from(value);
            }
            "--cases" => {
                let value = args.next().ok_or_else(usage)?;
                let parsed = value
                    .parse::<u32>()
                    .map_err(|_| format!("invalid --cases value: {value}"))?;
                if parsed == 0 {
                    return Err("--cases must be greater than zero".into());
                }
                keygen_cases_per_logn = parsed;
                sign_cases_per_logn = parsed;
            }
            "--keygen-cases" => {
                let value = args.next().ok_or_else(usage)?;
                keygen_cases_per_logn = value
                    .parse::<u32>()
                    .map_err(|_| format!("invalid --keygen-cases value: {value}"))?;
                if keygen_cases_per_logn == 0 {
                    return Err("--keygen-cases must be greater than zero".into());
                }
            }
            "--sign-cases" => {
                let value = args.next().ok_or_else(usage)?;
                sign_cases_per_logn = value
                    .parse::<u32>()
                    .map_err(|_| format!("invalid --sign-cases value: {value}"))?;
                if sign_cases_per_logn == 0 {
                    return Err("--sign-cases must be greater than zero".into());
                }
            }
            _ => return Err(usage()),
        }
    }

    if kind == ArtifactKind::All && out.is_some() {
        return Err("--out cannot be used with all/check-all; use --out-dir".into());
    }

    Ok(Options {
        mode,
        kind,
        out,
        out_dir,
        keygen_cases_per_logn,
        sign_cases_per_logn,
    })
}

#[cfg(feature = "deterministic-tests")]
fn usage() -> String {
    [
        "usage:",
        "  cargo run --features deterministic-tests --bin r1_artifacts -- all --out-dir artifacts --keygen-cases 10000 --sign-cases 1000",
        "  cargo run --features deterministic-tests --bin r1_artifacts -- check-all --out-dir artifacts --keygen-cases 10000 --sign-cases 1000",
        "  cargo run --features deterministic-tests --bin r1_artifacts -- keygen --out artifacts/ref-differential-keygen.json --keygen-cases 10000",
        "  cargo run --features deterministic-tests --bin r1_artifacts -- sign --out artifacts/ref-differential-sign.json --sign-cases 1000",
        "  cargo run --features deterministic-tests --bin r1_artifacts -- summary --out artifacts/ref-differential-summary.md --keygen-cases 10000 --sign-cases 1000",
    ]
    .join("\n")
}

#[cfg(feature = "deterministic-tests")]
fn resolve_output_path(options: &Options) -> Result<PathBuf, String> {
    if let Some(path) = &options.out {
        return Ok(path.clone());
    }
    let filename = match options.kind {
        ArtifactKind::Keygen => KEYGEN_ARTIFACT_FILENAME,
        ArtifactKind::Sign => SIGN_ARTIFACT_FILENAME,
        ArtifactKind::Summary => SUMMARY_ARTIFACT_FILENAME,
        ArtifactKind::All => return Err("internal error: all has no single output path".into()),
    };
    Ok(options.out_dir.join(filename))
}

#[cfg(feature = "deterministic-tests")]
fn write_or_check(path: &Path, contents: &str, mode: Mode) -> Result<(), String> {
    match mode {
        Mode::Generate => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|err| format!("create {}: {err}", parent.display()))?;
            }
            fs::write(path, contents).map_err(|err| format!("write {}: {err}", path.display()))?;
        }
        Mode::Check => {
            let existing =
                fs::read(path).map_err(|err| format!("read {}: {err}", path.display()))?;
            if existing != contents.as_bytes() {
                return Err(format!(
                    "{} is stale; regenerate it with the matching r1_artifacts command",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

#[cfg(feature = "deterministic-tests")]
fn ensure_keygen_clean(stats: KeygenStats) -> Result<(), String> {
    let total_failures = stats.pk_mismatches
        + stats.sk_mismatches
        + stats.derived_pk_mismatches
        + stats.decoded_pk_mismatches
        + stats.decoded_sk_mismatches
        + stats.decoded_derived_pk_mismatches;
    if total_failures == 0 {
        return Ok(());
    }
    Err(format!(
        "keygen mismatches: pk={}, sk={}, derived_pk={}, decoded_pk={}, decoded_sk={}, decoded_derived_pk={}",
        stats.pk_mismatches,
        stats.sk_mismatches,
        stats.derived_pk_mismatches,
        stats.decoded_pk_mismatches,
        stats.decoded_sk_mismatches,
        stats.decoded_derived_pk_mismatches,
    ))
}

#[cfg(feature = "deterministic-tests")]
fn ensure_sign_clean(stats: SignStats) -> Result<(), String> {
    let total_failures = stats.key_pk_mismatches
        + stats.key_sk_mismatches
        + stats.nonce_mismatches
        + stats.sig_mismatches
        + stats.rust_verify_rust_failures
        + stats.rust_verify_c_failures
        + stats.c_verify_rust_failures
        + stats.c_verify_c_failures;
    if total_failures == 0 {
        return Ok(());
    }
    Err(format!(
        "sign mismatches: key_pk={}, key_sk={}, nonce={}, sig={}, rust_verify_rust={}, rust_verify_c={}, c_verify_rust={}, c_verify_c={}",
        stats.key_pk_mismatches,
        stats.key_sk_mismatches,
        stats.nonce_mismatches,
        stats.sig_mismatches,
        stats.rust_verify_rust_failures,
        stats.rust_verify_c_failures,
        stats.c_verify_rust_failures,
        stats.c_verify_c_failures,
    ))
}

#[cfg(feature = "deterministic-tests")]
fn build_keygen_artifact(cases_per_logn: u32) -> Result<(String, KeygenStats), String> {
    let mut stats = KeygenStats::default();
    let mut out = String::new();
    let mut first = true;

    writeln!(&mut out, "{{").unwrap();
    writeln!(&mut out, "  \"artifact\": \"ref-differential-keygen\",").unwrap();
    writeln!(&mut out, "  \"version\": 1,").unwrap();
    writeln!(&mut out, "  \"cases_per_logn\": {cases_per_logn},").unwrap();
    writeln!(&mut out, "  \"entries\": [").unwrap();

    for case in 0..cases_per_logn {
        write_keygen_case_512(&mut out, &mut first, &mut stats, case)?;
    }
    for case in 0..cases_per_logn {
        write_keygen_case_1024(&mut out, &mut first, &mut stats, case)?;
    }

    out.push_str("\n  ],\n");
    writeln!(&mut out, "  \"summary\": {{").unwrap();
    writeln!(&mut out, "    \"total_cases\": {},", stats.total_cases).unwrap();
    writeln!(&mut out, "    \"pk_mismatches\": {},", stats.pk_mismatches).unwrap();
    writeln!(&mut out, "    \"sk_mismatches\": {},", stats.sk_mismatches).unwrap();
    writeln!(
        &mut out,
        "    \"derived_pk_mismatches\": {},",
        stats.derived_pk_mismatches
    )
    .unwrap();
    writeln!(
        &mut out,
        "    \"decoded_pk_mismatches\": {},",
        stats.decoded_pk_mismatches
    )
    .unwrap();
    writeln!(
        &mut out,
        "    \"decoded_sk_mismatches\": {},",
        stats.decoded_sk_mismatches
    )
    .unwrap();
    writeln!(
        &mut out,
        "    \"decoded_derived_pk_mismatches\": {}",
        stats.decoded_derived_pk_mismatches
    )
    .unwrap();
    writeln!(&mut out, "  }}").unwrap();
    writeln!(&mut out, "}}").unwrap();

    Ok((out, stats))
}

#[cfg(feature = "deterministic-tests")]
fn write_keygen_case_512(
    out: &mut String,
    first: &mut bool,
    stats: &mut KeygenStats,
    case: u32,
) -> Result<(), String> {
    let seed = differential_bytes(b"step-r1-keygen-512", case, 32);
    let c_ref = c_reference::keygen(9, &seed, 0);
    let rust = Falcon512::keygen_from_seed(&seed)
        .map_err(|err| format!("Falcon512 keygen failed for case {case}: {err:?}"))?;
    let rust_pk = rust.public.to_bytes();
    let rust_sk = rust.secret.to_bytes(Compression::None);
    let rust_derived_public = rust
        .secret
        .derive_public()
        .map_err(|err| format!("Falcon512 derive_public failed for case {case}: {err:?}"))?;
    let rust_derived_pk = rust_derived_public.to_bytes();
    let decoded_pk = PublicKey::<9>::from_bytes(&c_ref.pk)
        .map_err(|err| format!("Falcon512 decode public key failed for case {case}: {err:?}"))?;
    let decoded_sk = SecretKey::<9>::from_bytes(&c_ref.sk)
        .map_err(|err| format!("Falcon512 decode secret key failed for case {case}: {err:?}"))?;
    let decoded_sk_bytes = decoded_sk.to_bytes(Compression::None);
    let decoded_derived_public = decoded_sk.derive_public().map_err(|err| {
        format!("Falcon512 decoded derive_public failed for case {case}: {err:?}")
    })?;
    let decoded_derived_pk = decoded_derived_public.to_bytes();

    let pk_match = rust_pk.as_ref() == c_ref.pk.as_slice();
    let sk_match = rust_sk.as_ref() == c_ref.sk.as_slice();
    let derived_pk_match = rust_derived_pk.as_ref() == c_ref.pk.as_slice();
    let decoded_pk_match = decoded_pk.to_bytes() == c_ref.pk.as_slice();
    let decoded_sk_match = decoded_sk_bytes.as_ref() == c_ref.sk.as_slice();
    let decoded_derived_pk_match = decoded_derived_pk.as_ref() == c_ref.pk.as_slice();

    stats.total_cases += 1;
    stats.pk_mismatches += u32::from(!pk_match);
    stats.sk_mismatches += u32::from(!sk_match);
    stats.derived_pk_mismatches += u32::from(!derived_pk_match);
    stats.decoded_pk_mismatches += u32::from(!decoded_pk_match);
    stats.decoded_sk_mismatches += u32::from(!decoded_sk_match);
    stats.decoded_derived_pk_mismatches += u32::from(!decoded_derived_pk_match);

    write_keygen_entry(
        out,
        first,
        9,
        case,
        &seed,
        &c_ref.pk,
        &c_ref.sk,
        pk_match,
        sk_match,
        derived_pk_match,
        decoded_pk_match,
        decoded_sk_match,
        decoded_derived_pk_match,
        Some((!pk_match, rust_pk.as_ref())),
        Some((!sk_match, rust_sk.as_ref())),
        Some((!derived_pk_match, rust_derived_pk.as_ref())),
        Some((!decoded_pk_match, decoded_pk.to_bytes())),
        Some((!decoded_sk_match, decoded_sk_bytes.as_ref())),
        Some((!decoded_derived_pk_match, decoded_derived_pk.as_ref())),
    );
    Ok(())
}

#[cfg(feature = "deterministic-tests")]
fn write_keygen_case_1024(
    out: &mut String,
    first: &mut bool,
    stats: &mut KeygenStats,
    case: u32,
) -> Result<(), String> {
    let seed = differential_bytes(b"step-r1-keygen-1024", case, 32);
    let c_ref = c_reference::keygen(10, &seed, 0);
    let rust = Falcon1024::keygen_from_seed(&seed)
        .map_err(|err| format!("Falcon1024 keygen failed for case {case}: {err:?}"))?;
    let rust_pk = rust.public.to_bytes();
    let rust_sk = rust.secret.to_bytes(Compression::None);
    let rust_derived_public = rust
        .secret
        .derive_public()
        .map_err(|err| format!("Falcon1024 derive_public failed for case {case}: {err:?}"))?;
    let rust_derived_pk = rust_derived_public.to_bytes();
    let decoded_pk = PublicKey::<10>::from_bytes(&c_ref.pk)
        .map_err(|err| format!("Falcon1024 decode public key failed for case {case}: {err:?}"))?;
    let decoded_sk = SecretKey::<10>::from_bytes(&c_ref.sk)
        .map_err(|err| format!("Falcon1024 decode secret key failed for case {case}: {err:?}"))?;
    let decoded_sk_bytes = decoded_sk.to_bytes(Compression::None);
    let decoded_derived_public = decoded_sk.derive_public().map_err(|err| {
        format!("Falcon1024 decoded derive_public failed for case {case}: {err:?}")
    })?;
    let decoded_derived_pk = decoded_derived_public.to_bytes();

    let pk_match = rust_pk.as_ref() == c_ref.pk.as_slice();
    let sk_match = rust_sk.as_ref() == c_ref.sk.as_slice();
    let derived_pk_match = rust_derived_pk.as_ref() == c_ref.pk.as_slice();
    let decoded_pk_match = decoded_pk.to_bytes() == c_ref.pk.as_slice();
    let decoded_sk_match = decoded_sk_bytes.as_ref() == c_ref.sk.as_slice();
    let decoded_derived_pk_match = decoded_derived_pk.as_ref() == c_ref.pk.as_slice();

    stats.total_cases += 1;
    stats.pk_mismatches += u32::from(!pk_match);
    stats.sk_mismatches += u32::from(!sk_match);
    stats.derived_pk_mismatches += u32::from(!derived_pk_match);
    stats.decoded_pk_mismatches += u32::from(!decoded_pk_match);
    stats.decoded_sk_mismatches += u32::from(!decoded_sk_match);
    stats.decoded_derived_pk_mismatches += u32::from(!decoded_derived_pk_match);

    write_keygen_entry(
        out,
        first,
        10,
        case,
        &seed,
        &c_ref.pk,
        &c_ref.sk,
        pk_match,
        sk_match,
        derived_pk_match,
        decoded_pk_match,
        decoded_sk_match,
        decoded_derived_pk_match,
        Some((!pk_match, rust_pk.as_ref())),
        Some((!sk_match, rust_sk.as_ref())),
        Some((!derived_pk_match, rust_derived_pk.as_ref())),
        Some((!decoded_pk_match, decoded_pk.to_bytes())),
        Some((!decoded_sk_match, decoded_sk_bytes.as_ref())),
        Some((!decoded_derived_pk_match, decoded_derived_pk.as_ref())),
    );
    Ok(())
}

#[cfg(feature = "deterministic-tests")]
#[allow(clippy::too_many_arguments)]
fn write_keygen_entry(
    out: &mut String,
    first: &mut bool,
    logn: u32,
    case: u32,
    seed: &[u8],
    c_pk: &[u8],
    c_sk: &[u8],
    pk_match: bool,
    sk_match: bool,
    derived_pk_match: bool,
    decoded_pk_match: bool,
    decoded_sk_match: bool,
    decoded_derived_pk_match: bool,
    rust_pk: Option<(bool, &[u8])>,
    rust_sk: Option<(bool, &[u8])>,
    rust_derived_pk: Option<(bool, &[u8])>,
    decoded_pk: Option<(bool, impl AsRef<[u8]>)>,
    decoded_sk: Option<(bool, impl AsRef<[u8]>)>,
    decoded_derived_pk: Option<(bool, impl AsRef<[u8]>)>,
) {
    start_json_entry(out, first);
    writeln!(out, "      \"logn\": {logn},").unwrap();
    writeln!(out, "      \"case\": {case},").unwrap();
    writeln!(out, "      \"seed_hex\": \"{}\",", to_hex(seed)).unwrap();
    writeln!(
        out,
        "      \"expected_public_key_len\": {},",
        c_pk.len()
    )
    .unwrap();
    writeln!(
        out,
        "      \"expected_public_key_sha256\": \"{}\",",
        sha256_hex(c_pk)
    )
    .unwrap();
    writeln!(
        out,
        "      \"expected_secret_key_len\": {},",
        c_sk.len()
    )
    .unwrap();
    writeln!(
        out,
        "      \"expected_secret_key_sha256\": \"{}\",",
        sha256_hex(c_sk)
    )
    .unwrap();
    write_optional_hex_entry(out, "rust_public_key_hex", rust_pk);
    write_optional_hex_entry(out, "rust_secret_key_hex", rust_sk);
    write_optional_hex_entry(out, "rust_derived_public_key_hex", rust_derived_pk);
    write_optional_hex_entry_ref(out, "decoded_public_key_hex", decoded_pk);
    write_optional_hex_entry_ref(out, "decoded_secret_key_hex", decoded_sk);
    write_optional_hex_entry_ref(out, "decoded_derived_public_key_hex", decoded_derived_pk);
    writeln!(out, "      \"pk_match\": {pk_match},").unwrap();
    writeln!(out, "      \"sk_match\": {sk_match},").unwrap();
    writeln!(out, "      \"derived_pk_match\": {derived_pk_match},").unwrap();
    writeln!(out, "      \"decoded_pk_match\": {decoded_pk_match},").unwrap();
    writeln!(out, "      \"decoded_sk_match\": {decoded_sk_match},").unwrap();
    writeln!(
        out,
        "      \"decoded_derived_pk_match\": {decoded_derived_pk_match}"
    )
    .unwrap();
    end_json_entry(out);
}

#[cfg(feature = "deterministic-tests")]
fn build_sign_artifact(cases_per_logn: u32) -> Result<(String, SignStats), String> {
    let mut stats = SignStats::default();
    let mut out = String::new();
    let mut first = true;

    writeln!(&mut out, "{{").unwrap();
    writeln!(&mut out, "  \"artifact\": \"ref-differential-sign\",").unwrap();
    writeln!(&mut out, "  \"version\": 1,").unwrap();
    writeln!(&mut out, "  \"cases_per_logn\": {cases_per_logn},").unwrap();
    writeln!(&mut out, "  \"entries\": [").unwrap();

    for case in 0..cases_per_logn {
        write_sign_case_512(&mut out, &mut first, &mut stats, case)?;
    }
    for case in 0..cases_per_logn {
        write_sign_case_1024(&mut out, &mut first, &mut stats, case)?;
    }

    out.push_str("\n  ],\n");
    writeln!(&mut out, "  \"summary\": {{").unwrap();
    writeln!(&mut out, "    \"total_cases\": {},", stats.total_cases).unwrap();
    writeln!(
        &mut out,
        "    \"key_pk_mismatches\": {},",
        stats.key_pk_mismatches
    )
    .unwrap();
    writeln!(
        &mut out,
        "    \"key_sk_mismatches\": {},",
        stats.key_sk_mismatches
    )
    .unwrap();
    writeln!(
        &mut out,
        "    \"nonce_mismatches\": {},",
        stats.nonce_mismatches
    )
    .unwrap();
    writeln!(
        &mut out,
        "    \"sig_mismatches\": {},",
        stats.sig_mismatches
    )
    .unwrap();
    writeln!(
        &mut out,
        "    \"rust_verify_rust_failures\": {},",
        stats.rust_verify_rust_failures
    )
    .unwrap();
    writeln!(
        &mut out,
        "    \"rust_verify_c_failures\": {},",
        stats.rust_verify_c_failures
    )
    .unwrap();
    writeln!(
        &mut out,
        "    \"c_verify_rust_failures\": {},",
        stats.c_verify_rust_failures
    )
    .unwrap();
    writeln!(
        &mut out,
        "    \"c_verify_c_failures\": {}",
        stats.c_verify_c_failures
    )
    .unwrap();
    writeln!(&mut out, "  }}").unwrap();
    writeln!(&mut out, "}}").unwrap();

    Ok((out, stats))
}

#[cfg(feature = "deterministic-tests")]
fn write_sign_case_512(
    out: &mut String,
    first: &mut bool,
    stats: &mut SignStats,
    case: u32,
) -> Result<(), String> {
    write_sign_case::<9, Falcon512>(
        out,
        first,
        stats,
        case,
        b"step-r1-sign-key-512",
        b"step-r1-sign-seed-512",
        b"step-r1-sign-msg-512",
        Falcon512::keygen_from_seed,
    )
}

#[cfg(feature = "deterministic-tests")]
fn write_sign_case_1024(
    out: &mut String,
    first: &mut bool,
    stats: &mut SignStats,
    case: u32,
) -> Result<(), String> {
    write_sign_case::<10, Falcon1024>(
        out,
        first,
        stats,
        case,
        b"step-r1-sign-key-1024",
        b"step-r1-sign-seed-1024",
        b"step-r1-sign-msg-1024",
        Falcon1024::keygen_from_seed,
    )
}

#[cfg(feature = "deterministic-tests")]
fn write_sign_case<const LOGN: u32, Marker>(
    out: &mut String,
    first: &mut bool,
    stats: &mut SignStats,
    case: u32,
    key_tag: &[u8],
    sign_tag: &[u8],
    msg_tag: &[u8],
    keygen: fn(&[u8]) -> falcon2017::Result<falcon2017::Keypair<LOGN>>,
) -> Result<(), String> {
    let _ = std::marker::PhantomData::<Marker>;
    let key_seed = differential_bytes(key_tag, case, 32);
    let sign_seed = differential_bytes(sign_tag, case, 32);
    let msg = differential_bytes(msg_tag, case, 1 + (case % 257) as usize);
    let compression = if (case & 1) == 0 {
        Compression::None
    } else {
        Compression::Static
    };
    let c_key = c_reference::keygen(LOGN, &key_seed, 0);
    let rust = keygen(&key_seed)
        .map_err(|err| format!("Falcon{LOGN} keygen failed for sign case {case}: {err:?}"))?;
    let rust_pk = rust.public.to_bytes();
    let rust_sk = rust.secret.to_bytes(Compression::None);

    let key_pk_match = rust_pk.as_ref() == c_key.pk.as_slice();
    let key_sk_match = rust_sk.as_ref() == c_key.sk.as_slice();

    let mut sign_seed_array = [0u8; 32];
    sign_seed_array.copy_from_slice(&sign_seed);
    let mut rng = FixedSeedRng::new(sign_seed_array);
    let rust_sig = rust
        .secret
        .sign_ref(&msg, compression, &mut rng)
        .map_err(|err| format!("Falcon{LOGN} sign failed for case {case}: {err:?}"))?;
    let c_sig = c_reference::sign(&c_key.sk, &msg, &sign_seed, compression_code(compression));

    let nonce_match = rust_sig.nonce().as_bytes() == c_sig.nonce.as_slice();
    let sig_match = rust_sig.body_bytes() == c_sig.sig.as_slice();
    let rust_verify_rust_ok = rust.public.verify_detached(&msg, &rust_sig).is_ok();
    let rust_verify_c_ok =
        rust_verify_streaming::<LOGN>(&rust.public, &c_sig.nonce, &msg, &c_sig.sig);
    let c_verify_rust_status = c_reference::verify(
        c_key.pk.as_slice(),
        rust_sig.nonce().as_bytes(),
        &msg,
        rust_sig.body_bytes(),
    );
    let c_verify_c_status =
        c_reference::verify(c_key.pk.as_slice(), &c_sig.nonce, &msg, &c_sig.sig);

    stats.total_cases += 1;
    stats.key_pk_mismatches += u32::from(!key_pk_match);
    stats.key_sk_mismatches += u32::from(!key_sk_match);
    stats.nonce_mismatches += u32::from(!nonce_match);
    stats.sig_mismatches += u32::from(!sig_match);
    stats.rust_verify_rust_failures += u32::from(!rust_verify_rust_ok);
    stats.rust_verify_c_failures += u32::from(!rust_verify_c_ok);
    stats.c_verify_rust_failures += u32::from(c_verify_rust_status != 1);
    stats.c_verify_c_failures += u32::from(c_verify_c_status != 1);

    start_json_entry(out, first);
    writeln!(out, "      \"logn\": {LOGN},").unwrap();
    writeln!(out, "      \"case\": {case},").unwrap();
    writeln!(
        out,
        "      \"compression\": \"{}\",",
        compression_label(compression)
    )
    .unwrap();
    writeln!(out, "      \"key_seed_hex\": \"{}\",", to_hex(&key_seed)).unwrap();
    writeln!(out, "      \"sign_seed_hex\": \"{}\",", to_hex(&sign_seed)).unwrap();
    writeln!(out, "      \"msg_hex\": \"{}\",", to_hex(&msg)).unwrap();
    write_optional_hex_entry(
        out,
        "rust_public_key_hex",
        Some((!key_pk_match, rust_pk.as_ref())),
    );
    write_optional_hex_entry(
        out,
        "rust_secret_key_hex",
        Some((!key_sk_match, rust_sk.as_ref())),
    );
    write_optional_hex_entry(
        out,
        "rust_nonce_hex",
        Some((!nonce_match, rust_sig.nonce().as_bytes())),
    );
    write_optional_hex_entry(
        out,
        "rust_signature_hex",
        Some((!sig_match, rust_sig.body_bytes())),
    );
    writeln!(
        out,
        "      \"expected_nonce_hex\": \"{}\",",
        to_hex(&c_sig.nonce)
    )
    .unwrap();
    writeln!(
        out,
        "      \"expected_signature_hex\": \"{}\",",
        to_hex(&c_sig.sig)
    )
    .unwrap();
    writeln!(out, "      \"key_pk_match\": {key_pk_match},").unwrap();
    writeln!(out, "      \"key_sk_match\": {key_sk_match},").unwrap();
    writeln!(out, "      \"nonce_match\": {nonce_match},").unwrap();
    writeln!(out, "      \"sig_match\": {sig_match},").unwrap();
    writeln!(out, "      \"rust_verify_rust_ok\": {rust_verify_rust_ok},").unwrap();
    writeln!(out, "      \"rust_verify_c_ok\": {rust_verify_c_ok},").unwrap();
    writeln!(
        out,
        "      \"c_verify_rust_status\": {c_verify_rust_status},"
    )
    .unwrap();
    writeln!(out, "      \"c_verify_c_status\": {c_verify_c_status}").unwrap();
    end_json_entry(out);
    Ok(())
}

#[cfg(feature = "deterministic-tests")]
fn build_summary_artifact(
    keygen_cases_per_logn: u32,
    sign_cases_per_logn: u32,
    keygen: KeygenStats,
    sign: SignStats,
) -> String {
    let mut out = String::new();
    writeln!(&mut out, "# R1 Differential Summary").unwrap();
    writeln!(&mut out).unwrap();
    writeln!(&mut out, "- keygen cases per logn: {keygen_cases_per_logn}").unwrap();
    writeln!(&mut out, "- sign cases per logn: {sign_cases_per_logn}").unwrap();
    writeln!(&mut out, "- supported logn values: `9`, `10`").unwrap();
    writeln!(
        &mut out,
        "- generator command: `cargo run --features deterministic-tests --bin r1_artifacts -- all --out-dir artifacts --keygen-cases {keygen_cases_per_logn} --sign-cases {sign_cases_per_logn}`"
    )
    .unwrap();
    writeln!(
        &mut out,
        "- validation command: `cargo run --features deterministic-tests --bin r1_artifacts -- check-all --out-dir artifacts --keygen-cases {keygen_cases_per_logn} --sign-cases {sign_cases_per_logn}`"
    )
    .unwrap();
    writeln!(&mut out).unwrap();
    writeln!(&mut out, "## Keygen").unwrap();
    writeln!(&mut out).unwrap();
    writeln!(&mut out, "- total cases: {}", keygen.total_cases).unwrap();
    writeln!(
        &mut out,
        "- public-key mismatches: {}",
        keygen.pk_mismatches
    )
    .unwrap();
    writeln!(
        &mut out,
        "- secret-key mismatches: {}",
        keygen.sk_mismatches
    )
    .unwrap();
    writeln!(
        &mut out,
        "- derive-public mismatches: {}",
        keygen.derived_pk_mismatches
    )
    .unwrap();
    writeln!(
        &mut out,
        "- decoded public-key mismatches: {}",
        keygen.decoded_pk_mismatches
    )
    .unwrap();
    writeln!(
        &mut out,
        "- decoded secret-key mismatches: {}",
        keygen.decoded_sk_mismatches
    )
    .unwrap();
    writeln!(
        &mut out,
        "- decoded derive-public mismatches: {}",
        keygen.decoded_derived_pk_mismatches
    )
    .unwrap();
    writeln!(&mut out).unwrap();
    writeln!(&mut out, "## Sign").unwrap();
    writeln!(&mut out).unwrap();
    writeln!(&mut out, "- total cases: {}", sign.total_cases).unwrap();
    writeln!(
        &mut out,
        "- key public-key mismatches: {}",
        sign.key_pk_mismatches
    )
    .unwrap();
    writeln!(
        &mut out,
        "- key secret-key mismatches: {}",
        sign.key_sk_mismatches
    )
    .unwrap();
    writeln!(&mut out, "- nonce mismatches: {}", sign.nonce_mismatches).unwrap();
    writeln!(&mut out, "- signature mismatches: {}", sign.sig_mismatches).unwrap();
    writeln!(
        &mut out,
        "- Rust verify failures on Rust signatures: {}",
        sign.rust_verify_rust_failures
    )
    .unwrap();
    writeln!(
        &mut out,
        "- Rust verify failures on C signatures: {}",
        sign.rust_verify_c_failures
    )
    .unwrap();
    writeln!(
        &mut out,
        "- C verify failures on Rust signatures: {}",
        sign.c_verify_rust_failures
    )
    .unwrap();
    writeln!(
        &mut out,
        "- C verify failures on C signatures: {}",
        sign.c_verify_c_failures
    )
    .unwrap();
    out
}

#[cfg(feature = "deterministic-tests")]
fn rust_verify_streaming<const LOGN: u32>(
    public: &PublicKey<LOGN>,
    nonce_bytes: &[u8],
    msg: &[u8],
    sig_body: &[u8],
) -> bool {
    let prepared = match public.prepare() {
        Ok(prepared) => prepared,
        Err(_) => return false,
    };
    let nonce = Nonce::from_bytes(nonce_bytes);
    let split = msg.len() / 2;
    let mut verifier = prepared.verifier(&nonce);
    verifier.update(&msg[..split]);
    verifier.update(&msg[split..]);
    verifier.finalize(sig_body).is_ok()
}

#[cfg(feature = "deterministic-tests")]
fn compression_label(compression: Compression) -> &'static str {
    match compression {
        Compression::None => "none",
        Compression::Static => "static",
    }
}

#[cfg(feature = "deterministic-tests")]
fn compression_code(compression: Compression) -> u32 {
    match compression {
        Compression::None => 0,
        Compression::Static => 1,
    }
}

#[cfg(feature = "deterministic-tests")]
fn start_json_entry(out: &mut String, first: &mut bool) {
    if !*first {
        out.push_str(",\n");
    }
    *first = false;
    out.push_str("    {\n");
}

#[cfg(feature = "deterministic-tests")]
fn end_json_entry(out: &mut String) {
    out.push_str("    }");
}

#[cfg(feature = "deterministic-tests")]
fn write_optional_hex_entry(out: &mut String, key: &str, value: Option<(bool, &[u8])>) {
    if let Some((present, bytes)) = value {
        if present {
            writeln!(out, "      \"{key}\": \"{}\",", to_hex(bytes)).unwrap();
        }
    }
}

#[cfg(feature = "deterministic-tests")]
fn write_optional_hex_entry_ref<T: AsRef<[u8]>>(
    out: &mut String,
    key: &str,
    value: Option<(bool, T)>,
) {
    if let Some((present, bytes)) = value {
        if present {
            writeln!(out, "      \"{key}\": \"{}\",", to_hex(bytes.as_ref())).unwrap();
        }
    }
}

#[cfg(feature = "deterministic-tests")]
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    to_hex(digest.as_slice())
}

#[cfg(feature = "deterministic-tests")]
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        write!(&mut out, "{byte:02x}").unwrap();
    }
    out
}

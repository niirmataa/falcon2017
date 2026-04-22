use std::fmt::Write as _;
use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(feature = "deterministic-tests")]
use falcon2017::{Compression, Falcon1024, Falcon1024Keypair, Falcon512, Falcon512Keypair};
#[cfg(feature = "deterministic-tests")]
use falcon2017::{ExpandedSecretKeyCt, Keypair, SecretKey};
#[cfg(feature = "deterministic-tests")]
use rand_core::{CryptoRng, RngCore};

const JSON_FILENAME: &str = "ct-dynamic-timing.json";
const SUMMARY_FILENAME: &str = "ct-dynamic-timing.md";
const DEFAULT_SAMPLES_PER_CLASS: usize = 256;
const DEFAULT_EXPAND_BATCH: usize = 4;
const DEFAULT_SIGN_BATCH: usize = 4;
const KEYGEN_SEED_LEN: usize = 48;
const SIGN_SEED_LEN: usize = 48;
const SIGN_MSG_LEN: usize = 96;
const DUDECT_NOTICE_THRESHOLD: f64 = 4.5;
const DUDECT_STRONG_THRESHOLD: f64 = 10.0;

#[cfg(not(feature = "deterministic-tests"))]
fn main() {
    eprintln!("ct_timing requires --features deterministic-tests");
    std::process::exit(2);
}

#[cfg(feature = "deterministic-tests")]
fn main() {
    if let Err(err) = run() {
        eprintln!("ct_timing: {err}");
        std::process::exit(1);
    }
}

#[cfg(feature = "deterministic-tests")]
fn run() -> Result<(), String> {
    let options = parse_options()?;
    let report = TimingReport {
        generated_at_unix_s: unix_timestamp_s(),
        host_os: std::env::consts::OS,
        host_arch: std::env::consts::ARCH,
        hostname: std::env::var("HOSTNAME").ok(),
        samples_per_class: options.samples_per_class,
        expand_batch: options.expand_batch,
        sign_batch: options.sign_batch,
        notice_threshold: DUDECT_NOTICE_THRESHOLD,
        strong_threshold: DUDECT_STRONG_THRESHOLD,
        experiments: vec![
            build_expand_experiment::<9>(
                "expand_ct_strict_falcon512",
                falcon512_keygen_from_seed,
                options.samples_per_class,
                options.expand_batch,
                "fixed_secret_key",
                "varied_secret_keys",
            )?,
            build_expand_experiment::<10>(
                "expand_ct_strict_falcon1024",
                falcon1024_keygen_from_seed,
                options.samples_per_class,
                options.expand_batch,
                "fixed_secret_key",
                "varied_secret_keys",
            )?,
            build_sign_experiment::<9>(
                "sign_ct_strict_falcon512_none",
                falcon512_keygen_from_seed,
                options.samples_per_class,
                options.sign_batch,
                "fixed_key_message_rng",
                "varied_key_message_rng",
            )?,
            build_sign_experiment::<10>(
                "sign_ct_strict_falcon1024_none",
                falcon1024_keygen_from_seed,
                options.samples_per_class,
                options.sign_batch,
                "fixed_key_message_rng",
                "varied_key_message_rng",
            )?,
        ],
    };

    fs::create_dir_all(&options.out_dir)
        .map_err(|err| format!("create {}: {err}", options.out_dir.display()))?;
    let json = render_json(&report);
    let summary = render_summary(&report);
    fs::write(options.out_dir.join(JSON_FILENAME), json)
        .map_err(|err| format!("write {}: {err}", options.out_dir.display()))?;
    fs::write(options.out_dir.join(SUMMARY_FILENAME), summary)
        .map_err(|err| format!("write {}: {err}", options.out_dir.display()))?;
    Ok(())
}

#[cfg(feature = "deterministic-tests")]
struct Options {
    out_dir: PathBuf,
    samples_per_class: usize,
    expand_batch: usize,
    sign_batch: usize,
}

#[cfg(feature = "deterministic-tests")]
struct TimingReport {
    generated_at_unix_s: u64,
    host_os: &'static str,
    host_arch: &'static str,
    hostname: Option<String>,
    samples_per_class: usize,
    expand_batch: usize,
    sign_batch: usize,
    notice_threshold: f64,
    strong_threshold: f64,
    experiments: Vec<Experiment>,
}

#[cfg(feature = "deterministic-tests")]
struct Experiment {
    name: String,
    operation: &'static str,
    logn: u32,
    class_fixed: &'static str,
    class_varied: &'static str,
    batch: usize,
    fixed_durations_ns: Vec<u64>,
    varied_durations_ns: Vec<u64>,
    stats: TimingStats,
    seed_inventory: SeedInventory,
}

#[cfg(feature = "deterministic-tests")]
struct SeedInventory {
    fixed_key_tag: &'static str,
    varied_key_tag: &'static str,
    fixed_msg_tag: Option<&'static str>,
    varied_msg_tag: Option<&'static str>,
    fixed_rng_tag: Option<&'static str>,
    varied_rng_tag: Option<&'static str>,
}

#[cfg(feature = "deterministic-tests")]
struct TimingStats {
    mean_fixed_ns: f64,
    mean_varied_ns: f64,
    stddev_fixed_ns: f64,
    stddev_varied_ns: f64,
    median_fixed_ns: u64,
    median_varied_ns: u64,
    p95_fixed_ns: u64,
    p95_varied_ns: u64,
    min_fixed_ns: u64,
    max_fixed_ns: u64,
    min_varied_ns: u64,
    max_varied_ns: u64,
    welch_t: f64,
    abs_welch_t: f64,
}

#[cfg(feature = "deterministic-tests")]
struct SignInput<const LOGN: u32> {
    expanded: ExpandedSecretKeyCt<LOGN>,
    msg: Vec<u8>,
    rng_seed: Vec<u8>,
}

#[cfg(feature = "deterministic-tests")]
fn parse_options() -> Result<Options, String> {
    let mut out_dir = PathBuf::from("artifacts");
    let mut samples_per_class = DEFAULT_SAMPLES_PER_CLASS;
    let mut expand_batch = DEFAULT_EXPAND_BATCH;
    let mut sign_batch = DEFAULT_SIGN_BATCH;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out-dir" => {
                let value = args.next().ok_or_else(usage)?;
                out_dir = PathBuf::from(value);
            }
            "--samples-per-class" => {
                let value = args.next().ok_or_else(usage)?;
                samples_per_class = parse_usize_flag("--samples-per-class", &value)?;
            }
            "--expand-batch" => {
                let value = args.next().ok_or_else(usage)?;
                expand_batch = parse_usize_flag("--expand-batch", &value)?;
            }
            "--sign-batch" => {
                let value = args.next().ok_or_else(usage)?;
                sign_batch = parse_usize_flag("--sign-batch", &value)?;
            }
            "--help" | "-h" => return Err(usage()),
            _ => return Err(format!("unknown argument: {arg}\n\n{}", usage())),
        }
    }

    Ok(Options {
        out_dir,
        samples_per_class,
        expand_batch,
        sign_batch,
    })
}

#[cfg(feature = "deterministic-tests")]
fn usage() -> String {
    [
        "usage:",
        "  cargo run --release --features deterministic-tests --bin ct_timing -- --out-dir artifacts --samples-per-class 256 --expand-batch 4 --sign-batch 4",
        "",
        "flags:",
        "  --out-dir <path>",
        "  --samples-per-class <n>",
        "  --expand-batch <n>",
        "  --sign-batch <n>",
    ]
    .join("\n")
}

#[cfg(feature = "deterministic-tests")]
fn parse_usize_flag(name: &str, value: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("invalid {name} value: {value}"))?;
    if parsed == 0 {
        return Err(format!("{name} must be greater than zero"));
    }
    Ok(parsed)
}

#[cfg(feature = "deterministic-tests")]
fn unix_timestamp_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(feature = "deterministic-tests")]
fn falcon512_keygen_from_seed(seed: &[u8]) -> falcon2017::Result<Falcon512Keypair> {
    Falcon512::keygen_from_seed(seed)
}

#[cfg(feature = "deterministic-tests")]
fn falcon1024_keygen_from_seed(seed: &[u8]) -> falcon2017::Result<Falcon1024Keypair> {
    Falcon1024::keygen_from_seed(seed)
}

#[cfg(feature = "deterministic-tests")]
fn build_expand_experiment<const LOGN: u32>(
    name: &'static str,
    keygen: fn(&[u8]) -> falcon2017::Result<Keypair<LOGN>>,
    samples_per_class: usize,
    batch: usize,
    class_fixed: &'static str,
    class_varied: &'static str,
) -> Result<Experiment, String> {
    let fixed_key_tag = if LOGN == 9 {
        "ct-timing-expand-fixed-key-512"
    } else {
        "ct-timing-expand-fixed-key-1024"
    };
    let varied_key_tag = if LOGN == 9 {
        "ct-timing-expand-varied-key-512"
    } else {
        "ct-timing-expand-varied-key-1024"
    };

    let fixed_secret = keygen(&differential_bytes(
        fixed_key_tag.as_bytes(),
        0,
        KEYGEN_SEED_LEN,
    ))
    .map_err(|err| format!("fixed expand keygen {LOGN}: {err:?}"))?
    .secret;
    let mut varied = Vec::with_capacity(samples_per_class);
    for index in 0..samples_per_class {
        varied.push(
            keygen(&differential_bytes(
                varied_key_tag.as_bytes(),
                index as u32,
                KEYGEN_SEED_LEN,
            ))
            .map_err(|err| format!("varied expand keygen {LOGN}/{index}: {err:?}"))?
            .secret,
        );
    }

    let _ = measure_expand_batch(&fixed_secret, 1)?;
    let _ = measure_expand_batch(&varied[0], 1)?;

    let mut fixed_durations = Vec::with_capacity(samples_per_class);
    let mut varied_durations = Vec::with_capacity(samples_per_class);
    for index in 0..samples_per_class {
        if index % 2 == 0 {
            fixed_durations.push(measure_expand_batch(&fixed_secret, batch)?);
            varied_durations.push(measure_expand_batch(&varied[index], batch)?);
        } else {
            varied_durations.push(measure_expand_batch(&varied[index], batch)?);
            fixed_durations.push(measure_expand_batch(&fixed_secret, batch)?);
        }
    }

    Ok(Experiment {
        name: name.to_string(),
        operation: "expand_ct_strict",
        logn: LOGN,
        class_fixed,
        class_varied,
        batch,
        stats: compute_stats(&fixed_durations, &varied_durations),
        fixed_durations_ns: fixed_durations,
        varied_durations_ns: varied_durations,
        seed_inventory: SeedInventory {
            fixed_key_tag,
            varied_key_tag,
            fixed_msg_tag: None,
            varied_msg_tag: None,
            fixed_rng_tag: None,
            varied_rng_tag: None,
        },
    })
}

#[cfg(feature = "deterministic-tests")]
fn build_sign_experiment<const LOGN: u32>(
    name: &'static str,
    keygen: fn(&[u8]) -> falcon2017::Result<Keypair<LOGN>>,
    samples_per_class: usize,
    batch: usize,
    class_fixed: &'static str,
    class_varied: &'static str,
) -> Result<Experiment, String> {
    let fixed_key_tag = if LOGN == 9 {
        "ct-timing-sign-fixed-key-512"
    } else {
        "ct-timing-sign-fixed-key-1024"
    };
    let varied_key_tag = if LOGN == 9 {
        "ct-timing-sign-varied-key-512"
    } else {
        "ct-timing-sign-varied-key-1024"
    };
    let fixed_msg_tag = if LOGN == 9 {
        "ct-timing-sign-fixed-msg-512"
    } else {
        "ct-timing-sign-fixed-msg-1024"
    };
    let varied_msg_tag = if LOGN == 9 {
        "ct-timing-sign-varied-msg-512"
    } else {
        "ct-timing-sign-varied-msg-1024"
    };
    let fixed_rng_tag = if LOGN == 9 {
        "ct-timing-sign-fixed-rng-512"
    } else {
        "ct-timing-sign-fixed-rng-1024"
    };
    let varied_rng_tag = if LOGN == 9 {
        "ct-timing-sign-varied-rng-512"
    } else {
        "ct-timing-sign-varied-rng-1024"
    };

    let fixed_keypair = keygen(&differential_bytes(
        fixed_key_tag.as_bytes(),
        0,
        KEYGEN_SEED_LEN,
    ))
    .map_err(|err| format!("fixed sign keygen {LOGN}: {err:?}"))?;
    let fixed_input = SignInput {
        expanded: fixed_keypair
            .secret
            .expand_ct_strict()
            .map_err(|err| format!("fixed sign expand {LOGN}: {err:?}"))?,
        msg: differential_bytes(fixed_msg_tag.as_bytes(), 0, SIGN_MSG_LEN),
        rng_seed: differential_bytes(fixed_rng_tag.as_bytes(), 0, SIGN_SEED_LEN),
    };

    let mut varied = Vec::with_capacity(samples_per_class);
    for index in 0..samples_per_class {
        let keypair = keygen(&differential_bytes(
            varied_key_tag.as_bytes(),
            index as u32,
            KEYGEN_SEED_LEN,
        ))
        .map_err(|err| format!("varied sign keygen {LOGN}/{index}: {err:?}"))?;
        varied.push(SignInput {
            expanded: keypair
                .secret
                .expand_ct_strict()
                .map_err(|err| format!("varied sign expand {LOGN}/{index}: {err:?}"))?,
            msg: differential_bytes(varied_msg_tag.as_bytes(), index as u32, SIGN_MSG_LEN),
            rng_seed: differential_bytes(varied_rng_tag.as_bytes(), index as u32, SIGN_SEED_LEN),
        });
    }

    let _ = measure_sign_batch(
        &fixed_input.expanded,
        &fixed_input.msg,
        &fixed_input.rng_seed,
        1,
    )?;
    let _ = measure_sign_batch(&varied[0].expanded, &varied[0].msg, &varied[0].rng_seed, 1)?;

    let mut fixed_durations = Vec::with_capacity(samples_per_class);
    let mut varied_durations = Vec::with_capacity(samples_per_class);
    for index in 0..samples_per_class {
        if index % 2 == 0 {
            fixed_durations.push(measure_sign_batch(
                &fixed_input.expanded,
                &fixed_input.msg,
                &fixed_input.rng_seed,
                batch,
            )?);
            varied_durations.push(measure_sign_batch(
                &varied[index].expanded,
                &varied[index].msg,
                &varied[index].rng_seed,
                batch,
            )?);
        } else {
            varied_durations.push(measure_sign_batch(
                &varied[index].expanded,
                &varied[index].msg,
                &varied[index].rng_seed,
                batch,
            )?);
            fixed_durations.push(measure_sign_batch(
                &fixed_input.expanded,
                &fixed_input.msg,
                &fixed_input.rng_seed,
                batch,
            )?);
        }
    }

    Ok(Experiment {
        name: name.to_string(),
        operation: "sign_ct_strict",
        logn: LOGN,
        class_fixed,
        class_varied,
        batch,
        stats: compute_stats(&fixed_durations, &varied_durations),
        fixed_durations_ns: fixed_durations,
        varied_durations_ns: varied_durations,
        seed_inventory: SeedInventory {
            fixed_key_tag,
            varied_key_tag,
            fixed_msg_tag: Some(fixed_msg_tag),
            varied_msg_tag: Some(varied_msg_tag),
            fixed_rng_tag: Some(fixed_rng_tag),
            varied_rng_tag: Some(varied_rng_tag),
        },
    })
}

#[cfg(feature = "deterministic-tests")]
fn measure_expand_batch<const LOGN: u32>(
    secret: &SecretKey<LOGN>,
    batch: usize,
) -> Result<u64, String> {
    let start = Instant::now();
    for _ in 0..batch {
        let expanded = secret
            .expand_ct_strict()
            .map_err(|err| format!("expand_ct_strict<{LOGN}> failed: {err:?}"))?;
        black_box(expanded);
    }
    Ok(elapsed_ns(start))
}

#[cfg(feature = "deterministic-tests")]
fn measure_sign_batch<const LOGN: u32>(
    expanded: &ExpandedSecretKeyCt<LOGN>,
    msg: &[u8],
    rng_seed: &[u8],
    batch: usize,
) -> Result<u64, String> {
    let start = Instant::now();
    for _ in 0..batch {
        let mut rng = FixedByteRng::new(rng_seed);
        let sig = expanded
            .sign_ct_strict(black_box(msg), Compression::None, &mut rng)
            .map_err(|err| format!("sign_ct_strict<{LOGN}> failed: {err:?}"))?;
        black_box(sig);
    }
    Ok(elapsed_ns(start))
}

#[cfg(feature = "deterministic-tests")]
fn elapsed_ns(start: Instant) -> u64 {
    start.elapsed().as_nanos().max(1).min(u128::from(u64::MAX)) as u64
}

#[cfg(feature = "deterministic-tests")]
fn differential_bytes(tag: &[u8], index: u32, len: usize) -> Vec<u8> {
    assert!(!tag.is_empty(), "timing tag must not be empty");
    let mut out = vec![0u8; len];
    let mut state = index
        .wrapping_mul(0x9E37_79B9)
        .wrapping_add((tag.len() as u32).wrapping_mul(0x85EB_CA6B))
        ^ 0xA5A5_5A5A;
    for (offset, byte) in out.iter_mut().enumerate() {
        state ^= u32::from(tag[offset % tag.len()]);
        state = state.rotate_left(7).wrapping_mul(0x7FEB_352D);
        state = state.wrapping_add(0x846C_A68B ^ (offset as u32));
        *byte = (state >> ((offset & 3) * 8)) as u8;
    }
    out
}

#[cfg(feature = "deterministic-tests")]
struct FixedByteRng {
    bytes: Vec<u8>,
    pos: usize,
}

#[cfg(feature = "deterministic-tests")]
impl FixedByteRng {
    fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            pos: 0,
        }
    }

    fn next_byte(&mut self) -> u8 {
        let value = self.bytes[self.pos % self.bytes.len()];
        self.pos += 1;
        value
    }
}

#[cfg(feature = "deterministic-tests")]
impl RngCore for FixedByteRng {
    fn next_u32(&mut self) -> u32 {
        let mut out = [0u8; 4];
        self.fill_bytes(&mut out);
        u32::from_le_bytes(out)
    }

    fn next_u64(&mut self) -> u64 {
        let mut out = [0u8; 8];
        self.fill_bytes(&mut out);
        u64::from_le_bytes(out)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = self.next_byte();
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[cfg(feature = "deterministic-tests")]
impl CryptoRng for FixedByteRng {}

#[cfg(feature = "deterministic-tests")]
fn compute_stats(fixed: &[u64], varied: &[u64]) -> TimingStats {
    let mean_fixed = mean(fixed);
    let mean_varied = mean(varied);
    let var_fixed = sample_variance(fixed, mean_fixed);
    let var_varied = sample_variance(varied, mean_varied);
    let denom = ((var_fixed / fixed.len() as f64) + (var_varied / varied.len() as f64)).sqrt();
    let welch_t = if denom == 0.0 {
        0.0
    } else {
        (mean_fixed - mean_varied) / denom
    };

    TimingStats {
        mean_fixed_ns: mean_fixed,
        mean_varied_ns: mean_varied,
        stddev_fixed_ns: var_fixed.sqrt(),
        stddev_varied_ns: var_varied.sqrt(),
        median_fixed_ns: percentile(fixed, 0.50),
        median_varied_ns: percentile(varied, 0.50),
        p95_fixed_ns: percentile(fixed, 0.95),
        p95_varied_ns: percentile(varied, 0.95),
        min_fixed_ns: *fixed.iter().min().unwrap_or(&0),
        max_fixed_ns: *fixed.iter().max().unwrap_or(&0),
        min_varied_ns: *varied.iter().min().unwrap_or(&0),
        max_varied_ns: *varied.iter().max().unwrap_or(&0),
        welch_t,
        abs_welch_t: welch_t.abs(),
    }
}

#[cfg(feature = "deterministic-tests")]
fn mean(values: &[u64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().map(|&value| value as f64).sum::<f64>() / values.len() as f64
}

#[cfg(feature = "deterministic-tests")]
fn sample_variance(values: &[u64], mean: f64) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let sum = values
        .iter()
        .map(|&value| {
            let delta = value as f64 - mean;
            delta * delta
        })
        .sum::<f64>();
    sum / (values.len() as f64 - 1.0)
}

#[cfg(feature = "deterministic-tests")]
fn percentile(values: &[u64], quantile: f64) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let index = ((sorted.len() - 1) as f64 * quantile).round() as usize;
    sorted[index]
}

#[cfg(feature = "deterministic-tests")]
fn render_json(report: &TimingReport) -> String {
    let mut out = String::new();
    writeln!(&mut out, "{{").unwrap();
    writeln!(
        &mut out,
        "  \"generated_at_unix_s\": {},",
        report.generated_at_unix_s
    )
    .unwrap();
    writeln!(&mut out, "  \"host_os\": \"{}\",", report.host_os).unwrap();
    writeln!(&mut out, "  \"host_arch\": \"{}\",", report.host_arch).unwrap();
    match &report.hostname {
        Some(hostname) => writeln!(&mut out, "  \"hostname\": \"{}\",", hostname).unwrap(),
        None => writeln!(&mut out, "  \"hostname\": null,").unwrap(),
    };
    writeln!(
        &mut out,
        "  \"samples_per_class\": {},",
        report.samples_per_class
    )
    .unwrap();
    writeln!(&mut out, "  \"expand_batch\": {},", report.expand_batch).unwrap();
    writeln!(&mut out, "  \"sign_batch\": {},", report.sign_batch).unwrap();
    writeln!(
        &mut out,
        "  \"dudect_notice_threshold\": {:.1},",
        report.notice_threshold
    )
    .unwrap();
    writeln!(
        &mut out,
        "  \"dudect_strong_threshold\": {:.1},",
        report.strong_threshold
    )
    .unwrap();
    writeln!(&mut out, "  \"experiments\": [").unwrap();
    for (exp_index, experiment) in report.experiments.iter().enumerate() {
        writeln!(&mut out, "    {{").unwrap();
        writeln!(&mut out, "      \"name\": \"{}\",", experiment.name).unwrap();
        writeln!(
            &mut out,
            "      \"operation\": \"{}\",",
            experiment.operation
        )
        .unwrap();
        writeln!(&mut out, "      \"logn\": {},", experiment.logn).unwrap();
        writeln!(&mut out, "      \"batch\": {},", experiment.batch).unwrap();
        writeln!(
            &mut out,
            "      \"class_fixed\": \"{}\",",
            experiment.class_fixed
        )
        .unwrap();
        writeln!(
            &mut out,
            "      \"class_varied\": \"{}\",",
            experiment.class_varied
        )
        .unwrap();
        writeln!(&mut out, "      \"seed_inventory\": {{").unwrap();
        writeln!(
            &mut out,
            "        \"fixed_key_tag\": \"{}\",",
            experiment.seed_inventory.fixed_key_tag
        )
        .unwrap();
        writeln!(
            &mut out,
            "        \"varied_key_tag\": \"{}\",",
            experiment.seed_inventory.varied_key_tag
        )
        .unwrap();
        write_optional_json_field(
            &mut out,
            "fixed_msg_tag",
            experiment.seed_inventory.fixed_msg_tag,
            true,
            8,
        );
        write_optional_json_field(
            &mut out,
            "varied_msg_tag",
            experiment.seed_inventory.varied_msg_tag,
            true,
            8,
        );
        write_optional_json_field(
            &mut out,
            "fixed_rng_tag",
            experiment.seed_inventory.fixed_rng_tag,
            true,
            8,
        );
        write_optional_json_field(
            &mut out,
            "varied_rng_tag",
            experiment.seed_inventory.varied_rng_tag,
            false,
            8,
        );
        writeln!(&mut out, "      }},").unwrap();
        write_stats_json(&mut out, &experiment.stats, experiment.batch);
        writeln!(
            &mut out,
            "      \"fixed_durations_ns\": {},",
            render_u64_array(&experiment.fixed_durations_ns)
        )
        .unwrap();
        writeln!(
            &mut out,
            "      \"varied_durations_ns\": {}",
            render_u64_array(&experiment.varied_durations_ns)
        )
        .unwrap();
        if exp_index + 1 == report.experiments.len() {
            writeln!(&mut out, "    }}").unwrap();
        } else {
            writeln!(&mut out, "    }},").unwrap();
        }
    }
    writeln!(&mut out, "  ]").unwrap();
    writeln!(&mut out, "}}").unwrap();
    out
}

#[cfg(feature = "deterministic-tests")]
fn write_optional_json_field(
    out: &mut String,
    name: &str,
    value: Option<&str>,
    trailing_comma: bool,
    indent: usize,
) {
    let padding = " ".repeat(indent);
    match value {
        Some(value) => {
            if trailing_comma {
                writeln!(out, "{padding}\"{name}\": \"{value}\",").unwrap();
            } else {
                writeln!(out, "{padding}\"{name}\": \"{value}\"").unwrap();
            }
        }
        None => {
            if trailing_comma {
                writeln!(out, "{padding}\"{name}\": null,").unwrap();
            } else {
                writeln!(out, "{padding}\"{name}\": null").unwrap();
            }
        }
    }
}

#[cfg(feature = "deterministic-tests")]
fn write_stats_json(out: &mut String, stats: &TimingStats, batch: usize) {
    writeln!(out, "      \"stats\": {{").unwrap();
    writeln!(
        out,
        "        \"mean_fixed_ns\": {:.3},",
        stats.mean_fixed_ns
    )
    .unwrap();
    writeln!(
        out,
        "        \"mean_varied_ns\": {:.3},",
        stats.mean_varied_ns
    )
    .unwrap();
    writeln!(
        out,
        "        \"mean_fixed_per_call_ns\": {:.3},",
        stats.mean_fixed_ns / batch as f64
    )
    .unwrap();
    writeln!(
        out,
        "        \"mean_varied_per_call_ns\": {:.3},",
        stats.mean_varied_ns / batch as f64
    )
    .unwrap();
    writeln!(
        out,
        "        \"stddev_fixed_ns\": {:.3},",
        stats.stddev_fixed_ns
    )
    .unwrap();
    writeln!(
        out,
        "        \"stddev_varied_ns\": {:.3},",
        stats.stddev_varied_ns
    )
    .unwrap();
    writeln!(
        out,
        "        \"median_fixed_ns\": {},",
        stats.median_fixed_ns
    )
    .unwrap();
    writeln!(
        out,
        "        \"median_varied_ns\": {},",
        stats.median_varied_ns
    )
    .unwrap();
    writeln!(out, "        \"p95_fixed_ns\": {},", stats.p95_fixed_ns).unwrap();
    writeln!(out, "        \"p95_varied_ns\": {},", stats.p95_varied_ns).unwrap();
    writeln!(out, "        \"min_fixed_ns\": {},", stats.min_fixed_ns).unwrap();
    writeln!(out, "        \"max_fixed_ns\": {},", stats.max_fixed_ns).unwrap();
    writeln!(out, "        \"min_varied_ns\": {},", stats.min_varied_ns).unwrap();
    writeln!(out, "        \"max_varied_ns\": {},", stats.max_varied_ns).unwrap();
    writeln!(out, "        \"welch_t\": {:.6},", stats.welch_t).unwrap();
    writeln!(out, "        \"abs_welch_t\": {:.6}", stats.abs_welch_t).unwrap();
    writeln!(out, "      }},").unwrap();
}

#[cfg(feature = "deterministic-tests")]
fn render_u64_array(values: &[u64]) -> String {
    let mut out = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        let _ = write!(&mut out, "{value}");
    }
    out.push(']');
    out
}

#[cfg(feature = "deterministic-tests")]
fn render_summary(report: &TimingReport) -> String {
    let mut out = String::new();
    writeln!(&mut out, "# CT Dynamic Timing Summary").unwrap();
    writeln!(&mut out).unwrap();
    writeln!(
        &mut out,
        "- generated_at_unix_s: `{}`",
        report.generated_at_unix_s
    )
    .unwrap();
    writeln!(
        &mut out,
        "- host: `{}/{}`",
        report.host_os, report.host_arch
    )
    .unwrap();
    match &report.hostname {
        Some(hostname) => writeln!(&mut out, "- hostname: `{hostname}`").unwrap(),
        None => writeln!(&mut out, "- hostname: `unknown`").unwrap(),
    };
    writeln!(
        &mut out,
        "- samples per class: `{}`",
        report.samples_per_class
    )
    .unwrap();
    writeln!(
        &mut out,
        "- dudect-like thresholds: notice `|t| >= {:.1}`, strong `|t| >= {:.1}`",
        report.notice_threshold, report.strong_threshold
    )
    .unwrap();
    writeln!(&mut out).unwrap();
    writeln!(
        &mut out,
        "This is a dudect-like timing checkpoint, not an audit-closed constant-time proof."
    )
    .unwrap();
    writeln!(
        &mut out,
        "The fixed class repeats one deterministic input family; the varied class walks a deterministic seed family of equal public size."
    )
    .unwrap();
    writeln!(&mut out).unwrap();

    for experiment in &report.experiments {
        writeln!(&mut out, "## {}", experiment.name).unwrap();
        writeln!(&mut out).unwrap();
        writeln!(&mut out, "- operation: `{}`", experiment.operation).unwrap();
        writeln!(&mut out, "- logn: `{}`", experiment.logn).unwrap();
        writeln!(&mut out, "- batch: `{}`", experiment.batch).unwrap();
        writeln!(&mut out, "- fixed class: `{}`", experiment.class_fixed).unwrap();
        writeln!(&mut out, "- varied class: `{}`", experiment.class_varied).unwrap();
        writeln!(
            &mut out,
            "- mean fixed per call: `{:.1} ns`",
            experiment.stats.mean_fixed_ns / experiment.batch as f64
        )
        .unwrap();
        writeln!(
            &mut out,
            "- mean varied per call: `{:.1} ns`",
            experiment.stats.mean_varied_ns / experiment.batch as f64
        )
        .unwrap();
        writeln!(
            &mut out,
            "- median fixed batch: `{}` ns",
            experiment.stats.median_fixed_ns
        )
        .unwrap();
        writeln!(
            &mut out,
            "- median varied batch: `{}` ns",
            experiment.stats.median_varied_ns
        )
        .unwrap();
        writeln!(
            &mut out,
            "- p95 fixed batch: `{}` ns",
            experiment.stats.p95_fixed_ns
        )
        .unwrap();
        writeln!(
            &mut out,
            "- p95 varied batch: `{}` ns",
            experiment.stats.p95_varied_ns
        )
        .unwrap();
        writeln!(&mut out, "- Welch t: `{:.3}`", experiment.stats.welch_t).unwrap();
        writeln!(
            &mut out,
            "- interpretation: {}",
            interpret_t(experiment.stats.abs_welch_t)
        )
        .unwrap();
        writeln!(&mut out).unwrap();
    }

    out
}

#[cfg(feature = "deterministic-tests")]
fn interpret_t(abs_t: f64) -> &'static str {
    if abs_t >= DUDECT_STRONG_THRESHOLD {
        "strong class separation observed; this blocks any strong CT wording until investigated"
    } else if abs_t >= DUDECT_NOTICE_THRESHOLD {
        "class separation crossed the dudect notice threshold; rerun on a controlled host and investigate"
    } else {
        "no class separation observed at the current dudect notice threshold on this host"
    }
}

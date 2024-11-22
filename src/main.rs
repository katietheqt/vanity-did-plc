#![deny(rust_2018_idioms)]

use std::borrow::Cow;
use std::collections::HashMap;
use std::process::exit;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use clap::Parser;

use memmem::{Searcher, TwoWaySearcher};
use parking_lot::Mutex;
use rand::random;
use regex::Regex;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::insecure_ecdsa::{ConstantTableEntry, generate_ecdsa_constants, generate_signatures, SECP256K1};
use crate::math::Curve;
use crate::plc_op::{Service, SignedCreateOp, UnsignedCreateOp};

mod plc_op;
mod insecure_ecdsa;
mod math;

#[derive(Debug)]
struct Metrics {
    start_time: Instant,
    total_checked: u128,
}

#[derive(Debug, Parser)]
#[command(about, long_about = None)]
struct Args {
    /// The seed value for the DID.
    ///
    /// DIDs are generated sequentially, this sets the seed used to offset the initial index.
    #[arg(short, long, default_value_t = 0)]
    seed: u64,

    /// How many worker threads to spawn. Defaults to the number of CPU threads.
    #[arg(short, long, default_value_t = 0)]
    worker_threads: usize,

    /// If set, DIDs won't actually be created on the PLC directory.
    #[arg(long)]
    dry_run: bool,

    /// The URL of the PLC server to use.
    #[arg(long, default_value_t = Cow::Borrowed("https://plc.directory"))]
    plc_directory: Cow<'static, str>,

    /// The (secure) rotation key to register on created DIDs.
    ///
    /// An additional key will be added after this key, with a private key of 1 - this key is
    /// inherently insecure and should be removed as soon as possible. It has the DID
    /// `did:key:zQ3shVc2UkAfJCdc1TR8E66J85h48P43r93q8jGPkPpjF9Ef9`.
    rotation_key: String,

    /// The regex to match created DIDs against. This doesn't include the `did:plc:` prefix.
    regex: String,
}

/// This key has a private key of 1 - it's used for fast signature generation. The security
/// doesn't really matter as this key is used solely for signing the genesis operation, and is
/// then immediately revoked by the primary rotation key defined above.
const INSECURE_ROTATION_KEY: &'static str = "did:key:zQ3shVc2UkAfJCdc1TR8E66J85h48P43r93q8jGPkPpjF9Ef9";

/// After how many iterations of the DID loop to do before updating the metrics.
const METRIC_UPDATE_INTERVAL: u128 = 1000;

fn find_needle(buf: &[u8], marker: u8, length: usize) -> usize {
    let needle = vec![marker; length];
    let searcher = TwoWaySearcher::new(&needle);
    let index = searcher.search_in(buf).expect("couldn't find needle");
    index
}

fn crack_did(
    constants: Vec<ConstantTableEntry>, curve: Curve,
    mut unsigned_buf: Vec<u8>, unsigned_i_index: usize,
    mut signed_buf: Vec<u8>, signed_i_index: usize, signed_sig_index: usize,
    mut signed_op: SignedCreateOp, thread_idx: u64, shutdown_flag: Arc<AtomicBool>,
    output_channel: mpsc::UnboundedSender<(SignedCreateOp, String)>, regex: Regex,
    metrics: Arc<Mutex<Metrics>>,
) {
    let mut i = 0;
    let mut last_metrics_i = 0;

    while shutdown_flag.load(Ordering::Relaxed) {
        // generate a hex value for `i` and patch it into both buffers
        let i_hex = format!("{:032x}", i | (thread_idx as u128) << 96);
        unsigned_buf[unsigned_i_index..(unsigned_i_index + 32)].copy_from_slice(&i_hex.as_bytes());
        signed_buf[signed_i_index..(signed_i_index + 32)].copy_from_slice(&i_hex.as_bytes());

        // generate many valid signatures for the operation
        let sigs = generate_signatures(&unsigned_buf, &constants, curve);

        for sig in sigs {
            // patch the signature into the buffer
            signed_buf[signed_sig_index..(signed_sig_index + 86)].copy_from_slice(sig.as_bytes());

            // hash the signed operation to generate the DID
            let hash = Sha256::digest(&signed_buf);
            let mut digest = base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, hash.as_slice());
            digest.truncate(24);

            if regex.is_match(&digest) {
                // patch the values we used back into the struct for JSON serialization
                signed_op.op.services.get_mut("did_prefix").unwrap().endpoint = i_hex.clone();
                signed_op.sig = sig;

                let did = format!("did:plc:{}", &digest);

                if output_channel.send((signed_op.clone(), did)).is_err() {
                    return;
                }
            }
        }

        i += 1;

        if (i % METRIC_UPDATE_INTERVAL) == 0 {
            let mut metrics_guard = metrics.lock();
            metrics_guard.total_checked += (i - last_metrics_i) * constants.len() as u128;
            last_metrics_i = i;
        }
    }
}

#[tokio::main]
async fn main() {
    let args: Args = Args::parse();

    let seed = if args.seed == 0 {
        random()
    } else {
        args.seed
    };

    let regex = match Regex::new(&args.regex) {
        Ok(re) => re,
        Err(regex::Error::CompiledTooBig(_)) => {
            eprintln!("provided regex is too large");
            exit(1);
        }
        Err(regex::Error::Syntax(err)) => {
            eprintln!("syntax error in provided regex: {err}");
            exit(1);
        }
        _ => unreachable!()
    };

    let metrics = Arc::new(Mutex::new(Metrics {
        start_time: Instant::now(),
        total_checked: 0,
    }));

    eprintln!("using initial seed: {seed}");
    eprintln!("matching against: {}", args.regex);

    if args.dry_run {
        eprintln!("running with `--dry-run` (no DIDs will be submitted)");
    } else {
        eprintln!("submitting DIDs to {}", args.plc_directory);
    }

    // create ECDSA constants
    eprintln!("generating ECDSA constants...");
    let time = Instant::now();
    let curve = SECP256K1;
    let constants = generate_ecdsa_constants(curve);
    let time_taken = Instant::now() - time;
    eprintln!("generated ECDSA constants in {:.3}s", time_taken.as_secs_f64());

    // generate input values
    let op = UnsignedCreateOp {
        ty: "plc_operation".to_string(),
        verification_methods: HashMap::new(),
        rotation_keys: vec![args.rotation_key.to_string(), INSECURE_ROTATION_KEY.to_string()],
        also_known_as: vec![],
        services: HashMap::from([(
            "did_prefix".to_string(), Service {
                ty: format!(":3_{}", seed),
                endpoint: "00000000000000000000000000000000".to_string(),
            }
        )]),
        prev: None,
    };

    let cbor_buf = serde_ipld_dagcbor::to_vec(&op).expect("cbor encoding failed");
    let unsigned_i_index = find_needle(&cbor_buf, b'0', 32);

    let signed_op = SignedCreateOp {
        op: op.clone(),
        sig: "\x01".repeat(86),
    };

    let signed_cbor_buf = serde_ipld_dagcbor::to_vec(&signed_op).expect("cbor encoding failed");
    let signed_i_index = find_needle(&signed_cbor_buf, b'0', 32);
    let signed_sig_index = find_needle(&signed_cbor_buf, 1u8, 86);

    // spawn worker threads
    let running_flag = Arc::new(AtomicBool::new(true));

    let cracker_threads = if args.worker_threads == 0 {
        num_cpus::get()
    } else {
        args.worker_threads
    };

    let (output_channel_tx, mut output_channel_rx) = mpsc::unbounded_channel();
    let mut cracker_handles = Vec::new();

    for thread_idx in 0..cracker_threads {
        let thread_handle = thread::spawn({
            let constants = constants.clone();
            let cbor_buf = cbor_buf.clone();
            let signed_cbor_buf = signed_cbor_buf.clone();
            let signed_op = signed_op.clone();
            let running_flag = running_flag.clone();
            let output_channel_tx = output_channel_tx.clone();
            let regex = regex.clone();
            let metrics = metrics.clone();

            move || {
                crack_did(
                    constants, curve, cbor_buf, unsigned_i_index, signed_cbor_buf, signed_i_index,
                    signed_sig_index, signed_op, thread_idx as u64, running_flag, output_channel_tx,
                    regex, metrics
                )
            }
        });

        cracker_handles.push(thread_handle);
    }

    tokio::spawn(async move {
        let client = reqwest::Client::new();

        loop {
            let Some((signed_op, did)) = output_channel_rx.recv().await else { return };

            if !args.dry_run {
                let res = client.post(format!("{}/{}", &args.plc_directory, &did))
                    .json(&signed_op)
                    .send()
                    .await
                    .expect("web request failed");

                let body = res.text().await.expect("couldnt decode response body");
                println!("did {} got response body: {}", did, body);
            } else {
                println!("got did {} (`--dry-run` specified, no request sent)", did);
            }
        }
    });

    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(10)).await;

            {
                let metrics_guard = metrics.lock();
                let time_since_start = Instant::now() - metrics_guard.start_time;
                let average_per_sec = (metrics_guard.total_checked as f64 / time_since_start.as_secs_f64()) as u64;

                let seconds = time_since_start.as_secs() % 60;
                let minutes = (time_since_start.as_secs() / 60) % 60;
                let hours = (time_since_start.as_secs() / 60) / 60;
                eprintln!("running for: {:0>2}:{:0>2}:{:0>2}  avg per sec: {}", hours, minutes, seconds, average_per_sec);
            }
        }
    });

    // wait for ctrl-c
    tokio::signal::ctrl_c().await.expect("failed to register ctrl-c listener");
    eprintln!("stopping...");

    // wait for everything to finish
    running_flag.store(false, Ordering::Relaxed);

    for cracker_handle in cracker_handles {
        let _ = cracker_handle.join();
    }

    eprintln!("goodbye!");
}

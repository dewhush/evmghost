use evmghost::{
    probe::{json_report, passive_scan, probe},
    rpc::Rpc,
    scan_mode::ScanMode,
};
use std::process::ExitCode;

const USAGE: &str = "evmghost <0xDew> — on-chain recon & exploit-candidate finder

USAGE:
  evmghost <RPC_URL> <ADDRESS> [MODE] [--slot N | --scan CODE [CODE...]]

MODES:
  quick    pull bytecode, proxy resolution, storage slots 0-4   (default)
  deep     quick + all 4-byte selectors + vuln heuristics + storage slots 0-31
  slot     read 32-byte storage slot(s):  --slot 0 --slot 17 --slot 51
  proxy    resolve the proxy stack only (scriptable, one line per layer)
  events   decode recent logs: optional block window (default last 1000)
           evmghost <RPC> <ADDR> events 5000
  replay   replay a selector in the local VM with seeded chain state:
           evmghost <RPC> <ADDR> replay 0x40c10f19
  scan     passive on-chain scan over a block range without a target:
           --scan 19000000 19001000

NOTES:
  Public RPC (any chain): https://eth.llamarpc.com, https://rpc.ankr.com/eth ...
  No wallet keys needed — read-only JSON-RPC via eth_call/eth_getStorageAt.";

/// Public endpoints that worked during field testing. Tried in order; the
/// first that answers wins, and failures fall through to the next.
const RPC_FALLBACKS: [&str; 5] = [
    "https://ethereum-rpc.publicnode.com",
    "https://ethereum.publicnode.com",
    "https://1rpc.io/eth",
    "https://eth.drpc.org",
    "https://rpc.flashbots.net",
];

fn build_rpc(user: &str) -> Rpc {
    // an explicit http(s) URL is honoured as-is; otherwise treat the argument
    // as a chain hint and fan out over the built-in endpoint list
    if user.starts_with("http://") || user.starts_with("https://") {
        return Rpc::new(user);
    }
    match user {
        "eth" | "ethereum" | "mainnet" => Rpc::with_fallback(&RPC_FALLBACKS),
        _ => Rpc::new(user),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (_rpc_url, addr, mode, extra): (String, String, ScanMode, Vec<String>) = match parse(&args)
    {
        Some(v) => v,
        None => {
            println!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    // --json selects a machine-readable report instead of the human form
    let json = extra.iter().any(|a| a == "--json");
    let extra: Vec<String> = extra.into_iter().filter(|a| a != "--json").collect();

    let mut rpc = build_rpc(&args[0]);
    let chain = match rpc.chain_id() {
        Ok(id) => format!("chainId {id}"),
        Err(e) => {
            if !json {
                println!("[FAIL] RPC unreachable: {e}");
            } else {
                println!(r#"{{"error":"rpc unreachable: {e}"}}"#);
            }
            return ExitCode::from(1);
        }
    };

    if json {
        return match json_report(&mut rpc, &addr, &mode) {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                println!(r#"{{"error":"{e}"}}"#);
                ExitCode::from(1)
            }
        };
    }

    match mode {
        ScanMode::Scan => match passive_scan(&mut rpc, &chain, &extra) {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                println!("[FAIL] scan: {e}");
                ExitCode::from(1)
            }
        },
        _ => match probe(&mut rpc, &chain, &addr, &mode, &extra) {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                println!("[FAIL] {e}");
                ExitCode::from(1)
            }
        },
    }
}

fn parse(args: &[String]) -> Option<(String, String, ScanMode, Vec<String>)> {
    if args.len() < 2 {
        return None;
    }
    let mode = match args.get(2).map(String::as_str) {
        Some("deep") => ScanMode::Deep,
        Some("slot") => ScanMode::Slot,
        Some("scan") => ScanMode::Scan,
        Some("proxy") => ScanMode::Proxy,
        Some("events") | Some("logs") => ScanMode::Events,
        Some("replay") | Some("sim") => ScanMode::Replay,
        _ => ScanMode::Quick,
    };
    // address required for every mode except scan
    if mode != ScanMode::Scan && !args[1].starts_with("0x") {
        return None;
    }
    let extra = if args.len() > 3 {
        args[3..].to_vec()
    } else {
        Vec::new()
    };
    Some((args[0].clone(), args[1].clone(), mode, extra))
}

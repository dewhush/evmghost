use serde_json::json;
use ureq::Agent;

/// A multi-endpoint client: requests are tried against each URL in order and
/// re-tried on transient failures. Public endpoints rate-limit and die
/// without notice, so a single URL is not reliable enough to scan with.
pub struct Rpc {
    agent: Agent,
    urls: Vec<String>,
    /// index of the URL currently serving requests
    cur: usize,
    pub id: u64,
}

impl Rpc {
    /// single-endpoint client (back-compat with the existing call sites)
    pub fn new(url: &str) -> Self {
        Self::with_fallback(&[url])
    }

    /// multi-endpoint client; requests fall through to the next URL on failure
    pub fn with_fallback(urls: &[&str]) -> Self {
        Self {
            agent: Agent::new(),
            urls: urls.iter().map(|s| s.to_string()).collect(),
            cur: 0,
            id: 1,
        }
    }

    fn current_url(&self) -> &str {
        self.urls.get(self.cur).map(|s| s.as_str()).unwrap_or("")
    }

    /// advance to the next endpoint, wrapping around; returns false if every
    /// endpoint has been exhausted this round
    fn advance(&mut self) -> bool {
        let next = (self.cur + 1) % self.urls.len();
        if next == 0 {
            false
        } else {
            self.cur = next;
            true
        }
    }

    fn call(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        // try each endpoint in order, starting from the first. Endpoints fail
        // intermittently (rate limits, 504s), so a rotation continues until
        // one answers rather than giving up after one full sweep.
        self.cur = 0;
        let mut last_err = String::new();
        let mut tried = 0;
        while tried < self.urls.len() {
            tried += 1;
            let id = self.id;
            self.id += 1;
            let body =
                json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params.clone() });
            let url = self.current_url().to_string();
            match self.agent.post(&url).send_json(body) {
                Ok(r) => match r.into_string() {
                    Ok(text) => match serde_json::from_str::<serde_json::Value>(&text) {
                        Ok(v) => match &v["error"] {
                            serde_json::Value::Null => return Ok(v["result"].clone()),
                            e => {
                                last_err = format!("{method}: {e}");
                                if !self.advance() {
                                    // wrapped around: every endpoint failed once
                                    break;
                                }
                            }
                        },
                        Err(e) => {
                            last_err = format!("parse json: {e}");
                            if !self.advance() {
                                break;
                            }
                        }
                    },
                    Err(e) => {
                        last_err = format!("read body: {e}");
                        if !self.advance() {
                            break;
                        }
                    }
                },
                Err(e) => {
                    last_err = format!("POST {method} {url}: {e}");
                    if !self.advance() {
                        break;
                    }
                }
            }
        }
        Err(last_err)
    }

    pub fn chain_id(&mut self) -> Result<String, String> {
        let r = self.call("eth_chainId", json!([]))?;
        r.as_str()
            .map(String::from)
            .ok_or_else(|| "non-string chainId".into())
    }

    pub fn eth_call(&mut self, to: &str, data: &str, block: &str) -> Result<String, String> {
        let r = self.call("eth_call", json!([{ "to": to, "data": data }, block]))?;
        r.as_str()
            .map(String::from)
            .ok_or_else(|| "non-string call result".into())
    }

    pub fn storage(
        &mut self,
        addr: &str,
        slot: u64,
        block: Option<&str>,
    ) -> Result<String, String> {
        let block = block.unwrap_or("latest");
        let r = self.call(
            "eth_getStorageAt",
            json!([addr, format!("{slot:#x}"), block]),
        )?;
        r.as_str()
            .map(String::from)
            .ok_or_else(|| "non-string storage result".into())
    }

    /// Read a storage slot by its full 256-bit key, used for proxy slots like
    /// EIP-1967 whose value exceeds `u64`. Accepts "0x..." hex.
    pub fn storage_at_key(
        &mut self,
        addr: &str,
        key: &str,
        block: Option<&str>,
    ) -> Result<String, String> {
        let block = block.unwrap_or("latest");
        // eth_getStorageAt wants a hex quantity; a 32-byte hex string works
        let key = if key.starts_with("0x") || key.starts_with("0X") {
            key.to_string()
        } else {
            format!("0x{key}")
        };
        let r = self.call("eth_getStorageAt", json!([addr, key, block]))?;
        r.as_str()
            .map(String::from)
            .ok_or_else(|| "non-string storage result".into())
    }

    pub fn block_number(&mut self) -> Result<u64, String> {
        let r = self.call("eth_blockNumber", json!([]))?;
        u64::from_str_radix(
            r.as_str()
                .ok_or("non-string blockNumber")?
                .trim_start_matches("0x"),
            16,
        )
        .map_err(|e| format!("parse blockNumber: {e}"))
    }

    pub fn block_tx(&mut self, n: u64) -> Result<serde_json::Value, String> {
        let r = self.call("eth_getBlockByNumber", json!([format!("{n:#x}"), false]))?;
        if r.as_object().map(|o| o.is_empty()).unwrap_or(true) {
            return Err("block not found".into());
        }
        Ok(r)
    }

    fn raw_code(&mut self, addr: &str, block: &str) -> Result<String, String> {
        let r = self.call("eth_getCode", json!([addr, block]))?;
        r.as_str()
            .map(String::from)
            .ok_or_else(|| "non-string code result".into())
    }

    pub fn code(&mut self, addr: &str) -> Result<String, String> {
        self.raw_code(addr, "latest")
    }

    #[allow(dead_code)]
    pub fn code_at_block(&mut self, addr: &str, n: u64) -> Result<String, String> {
        self.raw_code(addr, &format!("{n:#x}"))
    }

    #[allow(dead_code)]
    pub fn tx(&mut self, hash: &str) -> Result<serde_json::Value, String> {
        self.call("eth_getTransactionByHash", json!([hash]))
    }

    #[allow(dead_code)]
    pub fn receipt(&mut self, hash: &str) -> Result<serde_json::Value, String> {
        self.call("eth_getTransactionReceipt", json!([hash]))
    }

    /// Read logs over a block range. Used to recover the events a contract
    /// emits, which is how real targets move funds and record approvals: the
    /// event surface often reveals privileged actors the code hides.
    pub fn logs(
        &mut self,
        addr: &str,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<LogEntry>, String> {
        let filter = json!({
            "fromBlock": format!("{from_block:#x}"),
            "toBlock": format!("{to_block:#x}"),
            "address": addr,
        });
        let v = self.call("eth_getLogs", json!([filter]))?;
        let arr = v
            .as_array()
            .ok_or_else(|| "logs: not an array".to_string())?;
        let mut out = Vec::new();
        for e in arr {
            let topics = e["topics"]
                .as_array()
                .map(|t| {
                    t.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            out.push(LogEntry {
                topics,
                data: e["data"].as_str().unwrap_or("0x").to_string(),
                block: e["blockNumber"].as_str().unwrap_or("0x0").to_string(),
                tx: e["transactionHash"].as_str().unwrap_or("").to_string(),
            });
        }
        Ok(out)
    }
}

/// A decoded log entry. The first topic is the event signature hash; the rest
/// are indexed arguments. `data` holds the non-indexed arguments.
#[derive(Clone, Debug)]
pub struct LogEntry {
    pub topics: Vec<String>,
    pub data: String,
    pub block: String,
    pub tx: String,
}

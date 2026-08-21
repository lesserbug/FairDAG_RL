// Copyright(C) Facebook, Inc. and its affiliates.
use anyhow::{Context, Result};
use bytes::BufMut as _;
use bytes::BytesMut;
use clap::{crate_name, crate_version, App, AppSettings};
use env_logger::Env;
use futures::future::join_all;
use futures::sink::SinkExt as _;
use log::{info, warn};
use rand::seq::SliceRandom;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio::time::{interval, sleep, Duration, Instant};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

const TIMEOUT: u64 = 60_000;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about("Benchmark client for Narwhal and Tusk.")
        .args_from_usage("<ADDRS> 'The network addresses of the nodes where to send txs, comma separated with no spaces'")
        .args_from_usage("--size=<INT> 'The size of each transaction in bytes'")
        .args_from_usage("--rate=<INT> 'The rate (txs/s) at which to send the transactions'")
        .args_from_usage("--client-id=<INT> 'Stable benchmark client index used to namespace transaction ids'")
        .args_from_usage("--nodes=[ADDR]... 'Network addresses that must be reachable before starting the benchmark.'")
        .setting(AppSettings::ArgRequiredElseHelp)
        .get_matches();

    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let targets = matches
        .value_of("ADDRS")
        .unwrap()
        .split(",")
        .filter_map(|s| s.parse::<SocketAddr>().ok())
        .collect::<Vec<_>>();
    let size = matches
        .value_of("size")
        .unwrap()
        .parse::<usize>()
        .context("The size of transactions must be a non-negative integer")?;
    let rate = matches
        .value_of("rate")
        .unwrap()
        .parse::<u64>()
        .context("The rate of transactions must be a non-negative integer")?;
    let client_id = matches
        .value_of("client-id")
        .unwrap()
        .parse::<u64>()
        .context("The client id must be a non-negative integer")?;
    let nodes = matches
        .values_of("nodes")
        .unwrap_or_default()
        .map(|x| x.parse::<SocketAddr>())
        .collect::<Result<Vec<_>, _>>()
        .context("Invalid socket address format")?;

    info!("Node addresses: {:?}", targets);

    // NOTE: This log entry is used to compute performance.
    info!("Transactions size: {} B", size);

    // NOTE: This log entry is used to compute performance.
    info!("Transactions rate: {} tx/s", rate);

    let client = Client {
        targets,
        size,
        rate,
        client_id,
        nodes,
    };

    // Wait for all nodes to be online and synchronized.
    client.wait().await;

    // Start the benchmark.
    client.send().await.context("Failed to submit transactions")
}

struct Client {
    targets: Vec<SocketAddr>,
    size: usize,
    rate: u64,
    client_id: u64,
    nodes: Vec<SocketAddr>,
}

const CLIENT_ID_BITS: u32 = 16;
const TX_SEQUENCE_BITS: u32 = u64::BITS - CLIENT_ID_BITS;
const MAX_CLIENT_ID: u64 = (1u64 << CLIENT_ID_BITS) - 1;
const MAX_TX_SEQUENCE: u64 = (1u64 << TX_SEQUENCE_BITS) - 1;

fn transaction_uid(client_id: u64, sequence: u64) -> Result<u64> {
    if client_id > MAX_CLIENT_ID {
        return Err(anyhow::Error::msg("Client id exceeds 16-bit namespace"));
    }
    if sequence > MAX_TX_SEQUENCE {
        return Err(anyhow::Error::msg(
            "Per-client transaction sequence exceeds 48-bit namespace",
        ));
    }
    Ok((client_id << TX_SEQUENCE_BITS) | sequence)
}

impl Client {
    pub async fn send(&self) -> Result<()> {
        const PRECISION: u64 = 20; // Sample precision.
        const BURST_DURATION: u64 = 1000 / PRECISION;

        // The transaction size must be at least 16 bytes to ensure all txs are different.
        if self.size < 9 {
            return Err(anyhow::Error::msg(
                "Transaction size must be at least 9 bytes",
            ));
        }

        // let n = self.targets.len();

        let futures = self.targets.iter().map(|target| async move {
            TcpStream::connect(target).await.expect("Could not connect")
        });

        let streams = join_all(futures).await;

        // Submit all transactions.
        let mut rng = rand::thread_rng();
        let burst = self.rate / PRECISION;
        let mut tx = BytesMut::with_capacity(self.size);
        let mut burst_counter = 0u64;
        let mut sequence = 0u64;
        let mut transports = Vec::with_capacity(streams.len());

        for stream in streams {
            let transport = Framed::new(stream, LengthDelimitedCodec::new());
            transports.push(transport);
        }
        let interval = interval(Duration::from_millis(BURST_DURATION));
        tokio::pin!(interval);

        // NOTE: This log entry is used to compute performance.
        info!("Start sending transactions");

        'main: loop {
            interval.as_mut().tick().await;
            let now = Instant::now();

            for x in 0..burst {
                let tx_id = transaction_uid(self.client_id, sequence)?;
                if x == burst_counter % burst {
                    // NOTE: This log entry is used to compute performance.
                    info!("Sending sample transaction {}", tx_id);

                    tx.put_u8(0u8); // Sample txs start with 0.
                    tx.put_u64(tx_id);
                } else {
                    tx.put_u8(1u8); // Standard txs start with 1.
                    tx.put_u64(tx_id);
                };
                sequence += 1;

                tx.resize(self.size, 0u8);
                let bytes = tx.split().freeze();
                transports.shuffle(&mut rng);
                for transport in &mut transports {
                    let dst_addr = {
                        if let Ok(a) = transport.get_ref().peer_addr() {
                            a
                        } else {
                            break 'main;
                        }
                    };
                    //info!("Sending tx from {}", src_addr);
                    let result = timeout(Duration::from_millis(TIMEOUT), async {
                        if let Err(e) = transport.send(bytes.clone()).await {
                            warn!("Failed to send transaction: {}", e);
                            // break 'main;

                            // we do not want to stop in case of error as we send to multiple workers anyway
                        }
                        "Done sending"
                    })
                    .await;
                    match result {
                        Ok(_) => {}
                        Err(err) => {
                            warn!("Sending timed out from {} after {}", dst_addr, err);
                        }
                    }
                }
            }
            if now.elapsed().as_millis() > BURST_DURATION as u128 {
                // NOTE: This log entry is used to compute performance.
                warn!("Transaction rate too high for this client");
            }
            burst_counter += 1;
        }
        Ok(())
    }

    pub async fn wait(&self) {
        // Wait for all nodes to be online.
        info!("Waiting for all nodes to be online...");
        join_all(self.nodes.iter().cloned().map(|address| {
            tokio::spawn(async move {
                while TcpStream::connect(address).await.is_err() {
                    sleep(Duration::from_millis(10)).await;
                }
            })
        }))
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::transaction_uid;

    #[test]
    fn transaction_ids_are_namespaced_by_client() {
        assert_ne!(
            transaction_uid(0, 7).unwrap(),
            transaction_uid(1, 7).unwrap()
        );
        assert_ne!(
            transaction_uid(1, 7).unwrap(),
            transaction_uid(1, 8).unwrap()
        );
    }
}

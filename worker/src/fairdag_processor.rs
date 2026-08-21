use crate::local_order_tracker::extract_tx_digest;
use crate::worker::WorkerMessage;
use config::Committee;
use crypto::PublicKey;
use fairdag_fairness::{
    CommittedSubdag, CommittedVertex, FairnessLayer, Round, TxDigest,
};
use log::{error, info, warn};
use primary::Certificate;
use std::time::Instant;
use store::Store;
use tokio::sync::mpsc::Receiver;

pub struct FairDagProcessor {
    store: Store,
    fairness_layer: FairnessLayer,
    sorted_keys: Vec<PublicKey>,
    rx_committed_subdags: Receiver<(Round, Vec<Certificate>)>,
}

impl FairDagProcessor {
    pub fn spawn(
        mut committee: Committee,
        store: Store,
        rx_committed_subdags: Receiver<(Round, Vec<Certificate>)>,
        fault_threshold: u64,
    ) {
        let n = committee.size();
        let f = fault_threshold as usize;

        let mut sorted_keys: Vec<PublicKey> = committee.authorities.keys().cloned().collect();
        sorted_keys.sort();

        let gamma = committee.get_gamma().unwrap();

        let fairness_layer = FairnessLayer::new(
            sorted_keys.clone(), 
            f,
            gamma
        );

        // Spawn with panic propagation — if the fairness layer panics,
        // the process aborts immediately instead of silently dropping the task.
        let handle = tokio::spawn(async move {
            Self {
                store,
                fairness_layer,
                sorted_keys,
                rx_committed_subdags,
            }
            .run()
            .await;
        });

        tokio::spawn(async move {
            if let Err(e) = handle.await {
                error!("FATAL: FairDagProcessor panicked: {:?}", e);
                std::process::abort();
            }
        });
    }

    async fn run(&mut self) {
        let mut subdag_count: u64 = 0;
        let mut batch_count: u64 = 0;

        while let Some((leader_round, certificates)) = self.rx_committed_subdags.recv().await {
            let batch_start = Instant::now();

            // ─────────────────────────────────────────────────────────────────
            // Step 1: Drain all queued subdags into a batch.
            // ─────────────────────────────────────────────────────────────────
            let mut batch_raw: Vec<(Round, Vec<Certificate>)> = vec![(leader_round, certificates)];
            while let Ok((r, c)) = self.rx_committed_subdags.try_recv() {
                batch_raw.push((r, c));
            }

            let batch_size = batch_raw.len();
            batch_count += 1;

            info!(
                "FAIRDAG_TIMING: batch #{} draining: {} subdags queued",
                batch_count, batch_size
            );

            // ─────────────────────────────────────────────────────────────────
            // Step 2: Extract all subdags (reads from store).
            // ─────────────────────────────────────────────────────────────────
            let extract_start = Instant::now();
            let mut subdags: Vec<CommittedSubdag> = Vec::with_capacity(batch_size);

            for (round, certs) in &batch_raw {
                subdag_count += 1;

                info!(
                    "FAIRDAG_TIMING: subdag #{} received: leader_round={} certs={}",
                    subdag_count, round, certs.len()
                );

                let sd_extract_start = Instant::now();
                let subdag = self.extract_subdag(*round, certs).await;
                let sd_extract_us = sd_extract_start.elapsed().as_micros();

                let total_entries: usize = subdag
                    .vertices
                    .iter()
                    .map(|v| v.ordering_entries.len())
                    .sum();

                info!(
                    "FAIRDAG_TIMING: subdag #{} extract done: {}us, vertices={} total_entries={}",
                    subdag_count, sd_extract_us, subdag.vertices.len(), total_entries
                );
                info!("FAIRDAG_TASK: name=extract us={}", sd_extract_us);

                subdags.push(subdag);
            }

            let extract_us = extract_start.elapsed().as_micros();
            let extract_ms = extract_us / 1000;

            // ─────────────────────────────────────────────────────────────────
            // Step 3: Process all subdags through the fairness layer.
            // ─────────────────────────────────────────────────────────────────
            let process_start = Instant::now();
            let mut total_fair_ordered: usize = 0;

            for (i, subdag) in subdags.iter().enumerate() {
                let sd_process_start = Instant::now();
                let fair_ordered = self.fairness_layer.process_subdag(subdag);
                let sd_process_ms = sd_process_start.elapsed().as_millis();

                let sd_num = subdag_count - (batch_size as u64) + (i as u64) + 1;

                info!(
                    "FAIRDAG_TIMING: subdag #{} process done: {}ms, fair_ordered={} total_time={}ms",
                    sd_num, sd_process_ms, fair_ordered.len(),
                    batch_start.elapsed().as_millis()
                );

                if !fair_ordered.is_empty() {
                    info!(
                        "FairDAG: outputting {} fair-ordered transactions from leader round {}",
                        fair_ordered.len(), subdag.leader_round
                    );
                    for tx_id in &fair_ordered {
                        info!("FairDAG-RL ordered transaction: {}", tx_id);
                    }
                    total_fair_ordered += fair_ordered.len();
                }
            }

            let process_ms = process_start.elapsed().as_millis();
            let total_ms = batch_start.elapsed().as_millis();

            info!(
                "FAIRDAG_TIMING: batch #{} done: batch_size={} extract={}ms process={}ms \
                 total={}ms fair_ordered={}",
                batch_count, batch_size, extract_ms, process_ms, total_ms, total_fair_ordered
            );
        }
    }

    async fn extract_subdag(
        &self,
        leader_round: Round,
        certificates: &[Certificate],
    ) -> CommittedSubdag {
        let mut vertices: Vec<CommittedVertex> = Vec::new();

        for cert in certificates {
            let author = cert.origin();
            let replica_index = self
                .sorted_keys
                .iter()
                .position(|k| *k == author)
                .expect("Certificate author not in committee");

            let mut ordering_entries: Vec<(TxDigest, u64)> = Vec::new();
            let mut batches_found = 0usize;
            let mut batches_missing = 0usize;

            for batch_digest in cert.header.payload.keys() {
                match self.store.clone().read(batch_digest.to_vec()).await {
                    Ok(Some(serialized_batch)) => {
                        batches_found += 1;
                        match bincode::deserialize::<WorkerMessage>(&serialized_batch) {
                            Ok(WorkerMessage::Batch(batch_entries, indirect_entries)) => {
                                append_batch_ordering_entries(
                                    &mut ordering_entries,
                                    batch_entries,
                                    indirect_entries,
                                );
                            }
                            Ok(_) => {
                                warn!("Unexpected message type for batch {:?}", batch_digest);
                            }
                            Err(e) => {
                                error!("Deser fail batch {:?}: {}", batch_digest, e);
                            }
                        }
                    }
                    Ok(None) => {
                        batches_missing += 1;
                    }
                    Err(e) => {
                        error!("Store read error batch {:?}: {}", batch_digest, e);
                    }
                }
            }

            info!(
                "FAIRDAG_TIMING: extract cert round={} replica={} batches found={} missing={} entries={}",
                cert.round(), replica_index, batches_found, batches_missing, ordering_entries.len()
            );

            vertices.push(CommittedVertex {
                replica: author,
                replica_index,
                round: cert.round(),
                ordering_entries,
            });
        }

        vertices.sort_by_key(|v| v.round);

        CommittedSubdag {
            leader_round,
            vertices,
        }
    }
}

/// Add every local-order observation carried by a committed worker batch.
///
/// Direct entries contain the full transaction, while indirect entries contain
/// the transaction id and the local OI assigned by the certificate author's
/// worker. FairDAG needs both forms to count observations across replicas.
fn append_batch_ordering_entries(
    ordering_entries: &mut Vec<(TxDigest, u64)>,
    direct_entries: Vec<(Vec<u8>, u64)>,
    indirect_entries: Vec<(TxDigest, u64)>,
) {
    ordering_entries.extend(
        direct_entries
            .into_iter()
            .map(|(tx_bytes, oi)| (extract_tx_digest(&tx_bytes), oi)),
    );
    ordering_entries.extend(indirect_entries);
}

#[cfg(test)]
mod tests {
    use super::append_batch_ordering_entries;

    #[test]
    fn committed_batch_keeps_direct_and_indirect_local_orders() {
        let direct_tx_id: u64 = 0x0102_0304_0506_0708;
        let mut direct_tx = vec![0u8];
        direct_tx.extend_from_slice(&direct_tx_id.to_be_bytes());

        let indirect_tx_id: u64 = 0x1112_1314_1516_1718;
        let mut ordering_entries = Vec::new();

        append_batch_ordering_entries(
            &mut ordering_entries,
            vec![(direct_tx, 7)],
            vec![(indirect_tx_id, 11)],
        );

        assert_eq!(
            ordering_entries,
            vec![(direct_tx_id, 7), (indirect_tx_id, 11)]
        );
    }
}

// Copyright(C) FairDAG-RL Implementation
// Implements the Fairness Layer of FairDAG-RL (Sections 6.1–6.3 of the paper).
//
// Batch-pipelined processing:
//   - Multiple subdags ingested sequentially (fast: ~2ms each)
//   - Expensive phases (catchup, weights, finalize) run once per batch
//   - Later subdags' OIs resolve earlier graphs' missing edges within same batch
//   - Finalization still sequential in round-increasing order (protocol requirement)
//
// To enable batching, modify FairDagProcessor::run() in fairdag_processor.rs:
//
//   // OLD:
//   while let Some((round, certs)) = self.rx_committed_subdags.recv().await {
//       let subdag = self.extract_subdag(round, &certs).await;
//       let ordered = self.fairness_layer.process_subdag(&subdag);
//       ...
//   }
//
//   // NEW:
//   while let Some((round, certs)) = self.rx_committed_subdags.recv().await {
//       let mut batch_raw = vec![(round, certs)];
//       while let Ok((r, c)) = self.rx_committed_subdags.try_recv() {
//           batch_raw.push((r, c));
//       }
//       let mut subdags = Vec::with_capacity(batch_raw.len());
//       for (r, c) in &batch_raw {
//           subdags.push(self.extract_subdag(*r, c).await);
//       }
//       let ordered = self.fairness_layer.process_subdag_batch(&subdags);
//       for tx_id in &ordered {
//           info!("FairDAG-RL ordered transaction: {}", tx_id);
//       }
//   }
//
// Other features: dense u32 indices, free-list recycling, compact unresolved-pair
// state (N ≤ 32), missing_pairs optimization, FAIRDAG_PERF logging.

use crypto::PublicKey;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

// =============================================================================
// Types
// =============================================================================

pub type TxDigest = u64;
pub type Round = u64;
pub type ReplicaIndex = usize;
pub type OrderingEntry = (TxDigest, u64);

// =============================================================================
// Constants
// =============================================================================

const NONE_LOCAL: u32 = u32::MAX;

// =============================================================================
// CommittedVertex / CommittedSubdag
// =============================================================================

#[derive(Clone, Debug)]
pub struct CommittedVertex {
    pub replica: PublicKey,
    pub replica_index: ReplicaIndex,
    pub round: Round,
    pub ordering_entries: Vec<(TxDigest, u64)>,
}

#[derive(Clone, Debug)]
pub struct CommittedSubdag {
    pub leader_round: Round,
    pub vertices: Vec<CommittedVertex>,
}

// =============================================================================
// Node types
// =============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeType {
    Blank,
    Shaded,
    Solid,
}

// =============================================================================
// Bitset helpers
// =============================================================================

#[inline(always)]
fn bit_get(bits: &[u64], idx: usize) -> bool {
    bits[idx >> 6] & (1u64 << (idx & 63)) != 0
}

#[inline(always)]
fn bit_set(bits: &mut [u64], idx: usize) {
    bits[idx >> 6] |= 1u64 << (idx & 63);
}

// =============================================================================
// Index helper for an unordered pair. Column-major triangular indexing keeps
// existing indices stable while a graph grows.
// =============================================================================

#[inline(always)]
fn pair_idx(i: u32, j: u32) -> usize {
    let (a, b) = if i < j { (i, j) } else { (j, i) };
    let a = a as usize;
    let b = b as usize;
    b * (b - 1) / 2 + a
}

// =============================================================================
// TransactionNode
// =============================================================================

#[derive(Clone, Debug)]
pub struct TransactionNode {
    pub digest: TxDigest,
    pub dense_idx: u32,
    pub node_type: NodeType,
    pub committed_ois: Vec<Option<u64>>,
    pub committed_rounds: Vec<Option<Round>>,
    pub graph_index: Option<usize>,
}

impl TransactionNode {
    fn new(digest: TxDigest, dense_idx: u32, n: usize) -> Self {
        TransactionNode {
            digest,
            dense_idx,
            node_type: NodeType::Blank,
            committed_ois: vec![None; n],
            committed_rounds: vec![None; n],
            graph_index: None,
        }
    }

    #[inline]
    fn appearance_count(&self, up_to_round: Round) -> usize {
        self.committed_rounds
            .iter()
            .filter(|r| matches!(r, Some(r) if *r <= up_to_round))
            .count()
    }
}

// =============================================================================
// DependencyGraph
// =============================================================================

#[derive(Clone, Copy, Debug)]
pub struct MissingPair {
    low: u32,
    high: u32,
    counted_mask: u32,
    low_to_high: u8,
    high_to_low: u8,
}

impl MissingPair {
    fn new(
        first: u32,
        second: u32,
        first_to_second: usize,
        second_to_first: usize,
        counted_mask: u32,
    ) -> Self {
        if first < second {
            MissingPair {
                low: first,
                high: second,
                counted_mask,
                low_to_high: first_to_second as u8,
                high_to_low: second_to_first as u8,
            }
        } else {
            MissingPair {
                low: second,
                high: first,
                counted_mask,
                low_to_high: second_to_first as u8,
                high_to_low: first_to_second as u8,
            }
        }
    }
}

pub struct DependencyGraph {
    pub round: Round,
    pub node_count: usize,
    pub local_to_global: Vec<u32>,
    pub global_to_local: Vec<u32>,
    pub edges: Vec<Vec<u32>>,
    pub edge_pair_count: usize,
    pub has_edge_pair: Vec<u64>,
    pub missing_pairs: Vec<MissingPair>,
    pub finalized: bool,
    pub final_order: Vec<TxDigest>,
}

impl DependencyGraph {
    fn new(round: Round) -> Self {
        DependencyGraph {
            round,
            node_count: 0,
            local_to_global: Vec::new(),
            global_to_local: Vec::new(),
            edges: Vec::new(),
            edge_pair_count: 0,
            has_edge_pair: Vec::new(),
            missing_pairs: Vec::new(),
            finalized: false,
            final_order: Vec::new(),
        }
    }

    #[inline]
    fn ensure_global_capacity(&mut self, global_idx: u32) {
        let needed = global_idx as usize + 1;
        if needed > self.global_to_local.len() {
            self.global_to_local.resize(needed, NONE_LOCAL);
        }
    }

    fn add_node(&mut self, global_dense_idx: u32) -> u32 {
        self.ensure_global_capacity(global_dense_idx);
        let existing = self.global_to_local[global_dense_idx as usize];
        if existing != NONE_LOCAL { return existing; }
        let local_idx = u32::try_from(self.node_count)
            .expect("FATAL: DependencyGraph contains more than u32::MAX nodes");
        self.local_to_global.push(global_dense_idx);
        self.global_to_local[global_dense_idx as usize] = local_idx;
        self.edges.push(Vec::with_capacity(16));
        self.node_count += 1;

        let pair_count = self.node_count * self.node_count.saturating_sub(1) / 2;
        let bit_words = (pair_count + 63) / 64;
        if bit_words > self.has_edge_pair.len() {
            self.has_edge_pair.resize(bit_words, 0);
        }
        local_idx
    }

    #[inline]
    fn get_local(&self, global_dense_idx: u32) -> Option<u32> {
        let g = global_dense_idx as usize;
        if g < self.global_to_local.len() {
            let l = self.global_to_local[g];
            if l != NONE_LOCAL { Some(l) } else { None }
        } else { None }
    }

    #[inline]
    fn is_tournament(&self) -> bool {
        let m = self.node_count;
        if m < 2 { return m <= 1; }
        self.edge_pair_count == m * (m - 1) / 2
    }

    #[inline]
    fn has_edge(&self, li: u32, lj: u32) -> bool {
        bit_get(&self.has_edge_pair, pair_idx(li, lj))
    }

    fn add_edge(&mut self, from: u32, to: u32) -> bool {
        let pidx = pair_idx(from, to);
        if bit_get(&self.has_edge_pair, pidx) { return false; }
        bit_set(&mut self.has_edge_pair, pidx);
        self.edge_pair_count += 1;
        self.edges[from as usize].push(to);
        true
    }

    fn release_memory(&mut self) {
        self.has_edge_pair = Vec::new();
        self.missing_pairs = Vec::new();
        for e in &mut self.edges { *e = Vec::new(); }
        self.edges = Vec::new();
        self.global_to_local = Vec::new();
    }
}

// =============================================================================
// Work descriptor: output of ingest, input to catchup
// =============================================================================

struct IngestResult {
    graph_idx: usize,
    newly_classified: Vec<u32>,
    round: Round,
}

// =============================================================================
// FairnessLayer
// =============================================================================

pub struct FairnessLayer {
    pub n: usize,
    pub f: usize,
    solid_threshold: usize,
    half_threshold: usize,

    digest_to_dense: HashMap<TxDigest, u32>,
    dense_to_digest: Vec<TxDigest>,
    next_dense_idx: u32,
    free_list: Vec<u32>,

    nodes: Vec<TransactionNode>,
    ordered_digests: HashSet<TxDigest>,

    graphs: Vec<DependencyGraph>,
    round_to_graph: HashMap<Round, usize>,

    output_sequence: Vec<TxDigest>,
    replica_indices: HashMap<PublicKey, ReplicaIndex>,

    use_hamiltonian_path: bool,
    pending_readd: Vec<u32>,

    subdag_count: u64,
    batch_count: u64,
}

impl FairnessLayer {
    pub fn new(committee_keys: Vec<PublicKey>, f: usize, gamma: f64) -> Self {
        let n = committee_keys.len();
        assert!(n <= 32, "FATAL: N={} exceeds 32 (counted bitmask is u32).", n);
        let solid_threshold = n - 2 * f;
        let non_blank_threshold = (((n as f64) * (1.0 - gamma) + gamma * (f as f64) + 1.0) * 1e10).round() / 1e10;
        let half_threshold = non_blank_threshold.floor() as usize;

        let replica_indices: HashMap<PublicKey, ReplicaIndex> = committee_keys
            .into_iter()
            .enumerate()
            .map(|(i, pk)| (pk, i))
            .collect();

        info!(
            "FairnessLayer initialized: n={}, f={}, solid_threshold={}, half_threshold={}",
            n, f, solid_threshold, half_threshold
        );

        FairnessLayer {
            n, f, solid_threshold, half_threshold,
            digest_to_dense: HashMap::new(),
            dense_to_digest: Vec::new(),
            next_dense_idx: 0,
            free_list: Vec::new(),
            nodes: Vec::new(),
            ordered_digests: HashSet::new(),
            graphs: Vec::new(),
            round_to_graph: HashMap::new(),
            output_sequence: Vec::new(),
            replica_indices,
            use_hamiltonian_path: false,
            pending_readd: Vec::new(),
            subdag_count: 0,
            batch_count: 0,
        }
    }

    // =========================================================================
    // Dense index management with recycling
    // =========================================================================

    fn get_or_create_dense(&mut self, digest: TxDigest) -> u32 {
        if let Some(&idx) = self.digest_to_dense.get(&digest) {
            return idx;
        }
        let idx = if let Some(recycled) = self.free_list.pop() {
            self.dense_to_digest[recycled as usize] = digest;
            self.nodes[recycled as usize] = TransactionNode::new(digest, recycled, self.n);
            recycled
        } else {
            let idx = self.next_dense_idx;
            if idx == u32::MAX {
                panic!("FATAL: Dense index overflow. free_list empty, live={}, ordered={}.",
                    self.digest_to_dense.len(), self.ordered_digests.len());
            }
            self.next_dense_idx = idx + 1;
            self.dense_to_digest.push(digest);
            self.nodes.push(TransactionNode::new(digest, idx, self.n));
            idx
        };
        self.digest_to_dense.insert(digest, idx);
        idx
    }

    fn recycle_ordered_tx(&mut self, digest: TxDigest) {
        self.ordered_digests.insert(digest);
        if let Some(dense) = self.digest_to_dense.remove(&digest) {
            self.dense_to_digest[dense as usize] = 0;
            self.nodes[dense as usize] = TransactionNode::new(0, dense, self.n);
            self.free_list.push(dense);
        }
    }

    // =========================================================================
    // PUBLIC API: Single subdag (backward compatible)
    // =========================================================================

    pub fn process_subdag(&mut self, subdag: &CommittedSubdag) -> Vec<TxDigest> {
        self.process_subdag_batch(&[subdag.clone()])
    }

    // =========================================================================
    // PUBLIC API: Batch processing (pipelined)
    //
    // Phase 1 (sequential, fast ~2ms/subdag):
    //   For each subdag: create graph, process pending readd,
    //   update nodes, classify → produces work descriptor.
    //
    // Phase 2 (expensive, batched):
    //   Catchup weights for ALL newly classified nodes across all graphs.
    //   By this point, ALL subdags' OIs are available, so missing edges
    //   from earlier graphs may resolve immediately from later subdags' data.
    //
    // Phase 3 (batched, fast with missing_pairs optimization):
    //   Update weights for missing pairs across ALL active graphs.
    //
    // Phase 4 (sequential, protocol requirement):
    //   Finalize graphs in round-increasing order.
    // =========================================================================

    pub fn process_subdag_batch(&mut self, subdags: &[CommittedSubdag]) -> Vec<TxDigest> {
        if subdags.is_empty() {
            return Vec::new();
        }

        let total_start = Instant::now();
        self.batch_count += 1;
        let batch_id = self.batch_count;
        let batch_size = subdags.len();

        let total_entries: usize = subdags.iter()
            .map(|s| s.vertices.iter().map(|v| v.ordering_entries.len()).sum::<usize>())
            .sum();

        let missing_before: usize = self.graphs.iter()
            .filter(|g| !g.finalized)
            .map(|g| g.missing_pairs.len())
            .sum();

        info!(
            "FAIRDAG_PERF: batch={} phase=start batch_size={} total_entries={} \
             active_graphs={} live_dense={} free_list={} ordered_total={} \
             missing_total={}",
            batch_id, batch_size, total_entries,
            self.graphs.iter().filter(|g| !g.finalized).count(),
            self.digest_to_dense.len(),
            self.free_list.len(),
            self.ordered_digests.len(),
            missing_before,
        );

        // =====================================================================
        // Phase 1: Sequential ingest (fast)
        // =====================================================================
        let t_ingest = Instant::now();
        let mut work_items: Vec<IngestResult> = Vec::with_capacity(batch_size);

        for subdag in subdags {
            self.subdag_count += 1;
            let result = self.ingest_subdag(subdag);
            work_items.push(result);
        }
        let t_ingest_done = t_ingest.elapsed();

        // =====================================================================
        // Phase 2: Catchup weights for all newly classified nodes
        //
        // By deferring catchup until after ALL subdags are ingested, later
        // subdags' committed_ois are already available when computing weights
        // for earlier graphs. This means missing edges may resolve within the
        // same batch — no waiting for a future batch.
        // =====================================================================
        let t_catchup = Instant::now();
        let mut total_catchup_pairs = 0usize;
        let mut total_catchup_edges = 0usize;
        let mut total_catchup_missing = 0usize;

        for item in &work_items {
            if item.newly_classified.is_empty() {
                continue;
            }
            let (pairs, edges, missing) =
                self.compute_catchup_weights_for_new_nodes(item.graph_idx, &item.newly_classified);
            total_catchup_pairs += pairs;
            total_catchup_edges += edges;
            total_catchup_missing += missing;
        }
        let t_catchup_done = t_catchup.elapsed();

        // =====================================================================
        // Phase 3: Update missing pairs across ALL active graphs
        // =====================================================================
        let t_weights = Instant::now();
        let (w_checked, w_incr, w_resolved) = self.update_weights_and_edges();
        let t_weights_done = t_weights.elapsed();

        // Log graph states.
        for (gi, g) in self.graphs.iter().enumerate() {
            if !g.finalized && g.node_count > 0 {
                let expected = if g.node_count > 1 {
                    g.node_count * (g.node_count - 1) / 2
                } else { 0 };
                info!(
                    "DIAG graph_state: G[{}] round={} nodes={} edges={}/{} \
                     missing_pairs={} is_tournament={}",
                    gi, g.round, g.node_count, g.edge_pair_count, expected,
                    g.missing_pairs.len(), g.is_tournament()
                );
            }
        }

        // =====================================================================
        // Phase 4: Finalize graphs in order
        // =====================================================================
        let t_finalize = Instant::now();
        let result = self.try_finalize_all_graphs();
        let t_finalize_done = t_finalize.elapsed();

        let t_total = total_start.elapsed();

        let missing_after: usize = self.graphs.iter()
            .filter(|g| !g.finalized)
            .map(|g| g.missing_pairs.len())
            .sum();

        info!(
            "FAIRDAG_PERF: batch={} phase=done batch_size={} total_us={} \
             ingest_us={} catchup_us={} weights_us={} finalize_us={} \
             catchup_pairs={} catchup_edges={} catchup_missing={} \
             w_checked={} w_incr={} w_resolved={} \
             finalized={} missing_before={} missing_after={}",
            batch_id, batch_size,
            t_total.as_micros(),
            t_ingest_done.as_micros(),
            t_catchup_done.as_micros(),
            t_weights_done.as_micros(),
            t_finalize_done.as_micros(),
            total_catchup_pairs, total_catchup_edges, total_catchup_missing,
            w_checked, w_incr, w_resolved,
            result.len(),
            missing_before, missing_after,
        );

        // Per-task lines aligned with Herring's task labels for apples-to-apples
        // comparison. FairDAG-RL has no claim mechanism, so solid_claim is
        // intentionally omitted. extract is emitted from the processor.
        //   phase1_support_weights := ingest + catchup
        //     (snapshot construction + the O(n·T²) pairwise weight pass)
        //   fair_update            := weights
        //     (FairDAG-RL's analog of FairUpdate: implicit missing-edge update)
        // The phase23_tarjan_missing line is emitted per finalize_ordering call.
        info!(
            "FAIRDAG_TASK: name=phase1_support_weights us={}",
            (t_ingest_done + t_catchup_done).as_micros()
        );
        info!(
            "FAIRDAG_TASK: name=fair_update us={}",
            t_weights_done.as_micros()
        );

        result
    }

    // =========================================================================
    // Phase 1: Ingest a single subdag (fast, sequential)
    //
    // Creates graph, processes pending readd, updates committed_ois,
    // classifies nodes. Returns work descriptor for Phase 2.
    // =========================================================================

    fn ingest_subdag(&mut self, subdag: &CommittedSubdag) -> IngestResult {
        let r = subdag.leader_round;
        let sd = self.subdag_count;

        let total_entries: usize = subdag.vertices.iter()
            .map(|v| v.ordering_entries.len()).sum();
        info!(
            "FairnessLayer: processing subdag leader_round={} vertices={} total_entries={}",
            r, subdag.vertices.len(), total_entries
        );

        // Create graph
        let graph_idx = self.graphs.len();
        self.graphs.push(DependencyGraph::new(r));
        self.round_to_graph.insert(r, graph_idx);

        // Process pending readd from prior finalizations
        self.process_pending_readd(graph_idx);

        // Update nodes
        let updated_nodes = self.update_nodes_from_subdag(subdag);

        // Classify
        let newly_classified = self.classify_and_add_nodes(r, graph_idx, &updated_nodes);

        info!(
            "FAIRDAG_PERF: sd={} phase=ingest round={} graph_idx={} \
             updated={} newly_classified={} graph_nodes={}",
            sd, r, graph_idx,
            updated_nodes.len(), newly_classified.len(),
            self.graphs[graph_idx].node_count,
        );

        IngestResult {
            graph_idx,
            newly_classified,
            round: r,
        }
    }

    // =========================================================================
    // Figure 8, Lines 3-10
    // =========================================================================

    fn update_nodes_from_subdag(&mut self, subdag: &CommittedSubdag) -> Vec<u32> {
        let mut updated_set: HashSet<u32> = HashSet::new();
        let r = subdag.leader_round;

        for vertex in &subdag.vertices {
            let i = vertex.replica_index;
            for &(d, oi) in &vertex.ordering_entries {
                if self.ordered_digests.contains(&d) {
                    continue;
                }
                let dense = self.get_or_create_dense(d);
                let node = &mut self.nodes[dense as usize];
                if node.committed_ois[i].is_none() {
                    node.committed_ois[i] = Some(oi);
                    node.committed_rounds[i] = Some(r);
                    updated_set.insert(dense);
                }
            }
        }

        let mut updated: Vec<u32> = updated_set.into_iter().collect();
        updated.sort_unstable();
        updated
    }

    // =========================================================================
    // Figure 8, Lines 11-18
    // =========================================================================

    fn classify_and_add_nodes(
        &mut self, r: Round, graph_idx: usize, updated_nodes: &[u32],
    ) -> Vec<u32> {
        let mut solid_count = 0usize;
        let mut shaded_count = 0usize;
        let mut blank_count = 0usize;
        let mut newly_classified: Vec<u32> = Vec::new();

        for &dense in updated_nodes {
            if self.nodes[dense as usize].node_type != NodeType::Blank {
                continue;
            }
            let ap = self.nodes[dense as usize].appearance_count(r);

            if ap >= self.solid_threshold {
                self.nodes[dense as usize].node_type = NodeType::Solid;
                self.nodes[dense as usize].graph_index = Some(graph_idx);
                self.graphs[graph_idx].add_node(dense);
                newly_classified.push(dense);
                solid_count += 1;
            } else if ap >= self.half_threshold {
                self.nodes[dense as usize].node_type = NodeType::Shaded;
                self.nodes[dense as usize].graph_index = Some(graph_idx);
                self.graphs[graph_idx].add_node(dense);
                newly_classified.push(dense);
                shaded_count += 1;
            } else {
                blank_count += 1;
            }
        }

        info!(
            "FairnessLayer: classify round={} G[{}] solid={} shaded={} blank={} total_in_graph={}",
            r, graph_idx, solid_count, shaded_count, blank_count,
            self.graphs[graph_idx].node_count
        );
        newly_classified
    }

    // =========================================================================
    // Phase 2: Catchup weights + populate missing_pairs
    // Returns (pairs_computed, edges_added, missing_added)
    // =========================================================================

    fn compute_catchup_weights_for_new_nodes(
        &mut self, graph_idx: usize, newly_classified: &[u32],
    ) -> (usize, usize, usize) {
        if newly_classified.is_empty() {
            return (0, 0, 0);
        }

        let newly_set: HashSet<u32> = newly_classified.iter().copied().collect();
        let mut edges_added = 0usize;
        let mut weights_computed = 0usize;
        let mut missing_added = 0usize;
        let n = self.n;
        let ht = self.half_threshold;

        for &d_dense in newly_classified {
            let d_local = self.graphs[graph_idx].get_local(d_dense).unwrap();
            let node_count = self.graphs[graph_idx].node_count;

            for li in 0..node_count {
                let d2_dense = self.graphs[graph_idx].local_to_global[li];
                if d2_dense == d_dense { continue; }
                let d2_local = li as u32;

                if newly_set.contains(&d2_dense) && d_dense > d2_dense {
                    continue;
                }

                let (w12, w21) = self.calculate_pairwise_weight(d_dense, d2_dense);
                weights_computed += 1;

                let mut mask: u32 = 0;
                for r in 0..n {
                    if self.nodes[d_dense as usize].committed_ois[r].is_some()
                        && self.nodes[d2_dense as usize].committed_ois[r].is_some()
                    {
                        mask |= 1u32 << r;
                    }
                }
                if w12 >= ht || w21 >= ht {
                    if w12 >= w21 {
                        self.graphs[graph_idx].add_edge(d_local, d2_local);
                    } else {
                        self.graphs[graph_idx].add_edge(d2_local, d_local);
                    }
                    edges_added += 1;
                } else {
                    self.graphs[graph_idx].missing_pairs.push(MissingPair::new(
                        d_local, d2_local, w12, w21, mask,
                    ));
                    missing_added += 1;
                }
            }
        }

        (weights_computed, edges_added, missing_added)
    }

    // =========================================================================
    // Phase 3: Pair-driven weight update across ALL active graphs
    // Returns (pairs_checked, incremented, edges_resolved)
    // =========================================================================

    fn update_weights_and_edges(&mut self) -> (usize, usize, usize) {
        let n = self.n;
        let ht = self.half_threshold as u8;
        let mut stat_checked: usize = 0;
        let mut stat_incr: usize = 0;
        let mut stat_resolved: usize = 0;

        for g_idx in 0..self.graphs.len() {
            if self.graphs[g_idx].finalized || self.graphs[g_idx].missing_pairs.is_empty() {
                continue;
            }

            let num_missing = self.graphs[g_idx].missing_pairs.len();
            let mut resolved: Vec<usize> = Vec::new();

            for pair_pos in 0..num_missing {
                let mut pair = self.graphs[g_idx].missing_pairs[pair_pos];

                if self.graphs[g_idx].has_edge(pair.low, pair.high) {
                    resolved.push(pair_pos);
                    continue;
                }

                stat_checked += 1;

                let di = self.graphs[g_idx].local_to_global[pair.low as usize];
                let dj = self.graphs[g_idx].local_to_global[pair.high as usize];

                for r in 0..n {
                    if pair.counted_mask & (1u32 << r) != 0 { continue; }
                    if let (Some(oi_i), Some(oi_j)) = (
                        self.nodes[di as usize].committed_ois[r],
                        self.nodes[dj as usize].committed_ois[r],
                    ) {
                        pair.counted_mask |= 1u32 << r;
                        if oi_i < oi_j {
                            pair.low_to_high += 1;
                        } else {
                            pair.high_to_low += 1;
                        }
                        stat_incr += 1;
                    }
                }

                self.graphs[g_idx].missing_pairs[pair_pos] = pair;

                if pair.low_to_high >= ht || pair.high_to_low >= ht {
                    if pair.low_to_high >= pair.high_to_low {
                        self.graphs[g_idx].add_edge(pair.low, pair.high);
                    } else {
                        self.graphs[g_idx].add_edge(pair.high, pair.low);
                    }
                    resolved.push(pair_pos);
                    stat_resolved += 1;
                }
            }

            resolved.sort_unstable();
            for &pos in resolved.iter().rev() {
                self.graphs[g_idx].missing_pairs.swap_remove(pos);
            }
        }

        (stat_checked, stat_incr, stat_resolved)
    }

    // =========================================================================
    // Phase 4: Finalization (sequential, round-increasing order)
    // =========================================================================

    fn try_finalize_all_graphs(&mut self) -> Vec<TxDigest> {
        let mut newly_ordered: Vec<TxDigest> = Vec::new();

        for g_idx in 0..self.graphs.len() {
            if self.graphs[g_idx].finalized { continue; }
            if self.graphs[g_idx].node_count == 0 {
                self.graphs[g_idx].finalized = true;
                continue;
            }

            if !self.graphs[g_idx].is_tournament() {
                info!(
                    "FAIRDAG_PERF: sd={} phase=finalize_blocked G[{}] round={} nodes={} \
                     edges={}/{} missing_pairs={} missing_edges={}",
                    self.subdag_count, g_idx, self.graphs[g_idx].round,
                    self.graphs[g_idx].node_count,
                    self.graphs[g_idx].edge_pair_count,
                    self.graphs[g_idx].node_count * (self.graphs[g_idx].node_count - 1) / 2,
                    self.graphs[g_idx].missing_pairs.len(),
                    (self.graphs[g_idx].node_count * (self.graphs[g_idx].node_count - 1) / 2)
                        .saturating_sub(self.graphs[g_idx].edge_pair_count),
                );
                break;
            }

            info!(
                "FairnessLayer: graph {} (round {}) is a tournament with {} nodes — finalizing",
                g_idx, self.graphs[g_idx].round, self.graphs[g_idx].node_count
            );

            let order = self.finalize_ordering(g_idx);
            newly_ordered.extend(order);
        }

        newly_ordered
    }

    fn finalize_ordering(&mut self, graph_idx: usize) -> Vec<TxDigest> {
        let t_phase23 = Instant::now();
        let node_count = self.graphs[graph_idx].node_count;

        let sccs = tarjan_scc_dense(node_count, &self.graphs[graph_idx].edges);
        let topo_order =
            topological_sort_sccs_dense(&sccs, &self.graphs[graph_idx].edges, node_count);

        let mut last_solid_pos: Option<usize> = None;
        for (pos, &scc_idx) in topo_order.iter().enumerate() {
            let has_solid = sccs[scc_idx].iter().any(|&li| {
                let dense = self.graphs[graph_idx].local_to_global[li as usize];
                self.nodes[dense as usize].node_type == NodeType::Solid
            });
            if has_solid { last_solid_pos = Some(pos); }
        }

        let mut ordered_digests: Vec<TxDigest> = Vec::new();
        let mut to_readd: Vec<u32> = Vec::new();

        match last_solid_pos {
            Some(cutoff) => {
                for (pos, &scc_idx) in topo_order.iter().enumerate() {
                    let scc = &sccs[scc_idx];
                    if pos <= cutoff {
                        let path = if self.use_hamiltonian_path {
                            hamiltonian_path_dense(scc, &self.graphs[graph_idx].edges)
                        } else {
                            let mut sorted = scc.clone();
                            sorted.sort_by_key(|&li| {
                                self.graphs[graph_idx].local_to_global[li as usize]
                            });
                            sorted
                        };
                        for &li in &path {
                            let dense = self.graphs[graph_idx].local_to_global[li as usize];
                            ordered_digests.push(self.nodes[dense as usize].digest);
                        }
                    } else {
                        for &li in scc {
                            let dense = self.graphs[graph_idx].local_to_global[li as usize];
                            to_readd.push(dense);
                        }
                    }
                }
            }
            None => {
                warn!("FairnessLayer: graph {} tournament with no solid nodes — deferring", graph_idx);
                info!("FAIRDAG_TASK: name=phase23_tarjan_missing us={}", t_phase23.elapsed().as_micros());
                return Vec::new();
            }
        }

        info!(
            "FAIRDAG_TASK: name=phase23_tarjan_missing us={}",
            t_phase23.elapsed().as_micros()
        );

        self.graphs[graph_idx].finalized = true;
        self.graphs[graph_idx].final_order = ordered_digests.clone();
        self.output_sequence.extend(&ordered_digests);

        for &d in &ordered_digests {
            self.recycle_ordered_tx(d);
        }

        if !to_readd.is_empty() {
            let next_graph_idx = self.find_next_unfinalized_graph(graph_idx);
            match next_graph_idx {
                Some(next_idx) => {
                    self.readd_nodes_to_graph(to_readd, next_idx);
                }
                None => {
                    for &dense in &to_readd {
                        self.nodes[dense as usize].node_type = NodeType::Blank;
                        self.nodes[dense as usize].graph_index = None;
                    }
                    self.pending_readd.extend(to_readd);
                }
            }
        }

        self.graphs[graph_idx].release_memory();

        // This log line is parsed by logs.py — DO NOT CHANGE FORMAT.
        info!(
            "FairnessLayer: finalized {} transactions from graph {} (round {}). Total ordered: {}",
            ordered_digests.len(), graph_idx,
            self.graphs[graph_idx].round, self.output_sequence.len()
        );

        ordered_digests
    }

    fn find_next_unfinalized_graph(&self, after_idx: usize) -> Option<usize> {
        for idx in (after_idx + 1)..self.graphs.len() {
            if !self.graphs[idx].finalized { return Some(idx); }
        }
        None
    }

    // =========================================================================
    // Re-add nodes to graph (also populates missing_pairs)
    // =========================================================================

    fn readd_nodes_to_graph(&mut self, to_readd: Vec<u32>, target_graph_idx: usize) {
        let r_prime = self.graphs[target_graph_idx].round;
        let n = self.n;
        let ht = self.half_threshold;

        for &dense in &to_readd {
            let ap = self.nodes[dense as usize].appearance_count(r_prime);

            if ap >= self.solid_threshold {
                self.nodes[dense as usize].node_type = NodeType::Solid;
            } else if ap >= ht {
                self.nodes[dense as usize].node_type = NodeType::Shaded;
            } else {
                self.nodes[dense as usize].node_type = NodeType::Blank;
                self.nodes[dense as usize].graph_index = None;
                self.pending_readd.push(dense);
                continue;
            }

            self.nodes[dense as usize].graph_index = Some(target_graph_idx);
            let d_local = self.graphs[target_graph_idx].add_node(dense);

            let node_count = self.graphs[target_graph_idx].node_count;

            for li in 0..node_count {
                let d2_dense = self.graphs[target_graph_idx].local_to_global[li];
                if d2_dense == dense { continue; }
                let d2_local = li as u32;

                let (w12, w21) = self.calculate_pairwise_weight(dense, d2_dense);

                let mut mask: u32 = 0;
                for r in 0..n {
                    if self.nodes[dense as usize].committed_ois[r].is_some()
                        && self.nodes[d2_dense as usize].committed_ois[r].is_some()
                    {
                        mask |= 1u32 << r;
                    }
                }
                if w12 >= ht || w21 >= ht {
                    if !self.graphs[target_graph_idx].has_edge(d_local, d2_local) {
                        if w12 >= w21 {
                            self.graphs[target_graph_idx].add_edge(d_local, d2_local);
                        } else {
                            self.graphs[target_graph_idx].add_edge(d2_local, d_local);
                        }
                    }
                } else {
                    self.graphs[target_graph_idx].missing_pairs.push(MissingPair::new(
                        d_local, d2_local, w12, w21, mask,
                    ));
                }
            }
        }
    }

    // =========================================================================
    // Pairwise weight calculation
    // =========================================================================

    fn calculate_pairwise_weight(&self, dense1: u32, dense2: u32) -> (usize, usize) {
        let node1 = &self.nodes[dense1 as usize];
        let node2 = &self.nodes[dense2 as usize];
        let mut w12: usize = 0;
        let mut w21: usize = 0;
        for i in 0..self.n {
            if let (Some(oi1), Some(oi2)) = (node1.committed_ois[i], node2.committed_ois[i]) {
                if oi1 < oi2 { w12 += 1; } else { w21 += 1; }
            }
        }
        (w12, w21)
    }

    // =========================================================================
    // Pending re-add processing
    // =========================================================================

    fn process_pending_readd(&mut self, graph_idx: usize) {
        if self.pending_readd.is_empty() { return; }

        let pending: Vec<u32> = self.pending_readd.drain(..)
            .filter(|&d| !self.ordered_digests.contains(&self.nodes[d as usize].digest))
            .collect();

        if !pending.is_empty() {
            self.readd_nodes_to_graph(pending, graph_idx);
        }
    }

    // =========================================================================
    // Public accessors
    // =========================================================================

    pub fn get_output_sequence(&self) -> &[TxDigest] {
        &self.output_sequence
    }

    pub fn pending_count(&self) -> usize {
        self.digest_to_dense.len()
    }

    pub fn replica_index(&self, pk: &PublicKey) -> Option<ReplicaIndex> {
        self.replica_indices.get(pk).copied()
    }
}

// =============================================================================
// Tarjan's SCC
// =============================================================================

fn tarjan_scc_dense(node_count: usize, edges: &[Vec<u32>]) -> Vec<Vec<u32>> {
    let mut dfn = vec![0i32; node_count];
    let mut low = vec![0i32; node_count];
    let mut on_stack = vec![false; node_count];
    let mut stack: Vec<u32> = Vec::with_capacity(node_count);
    let mut sccs: Vec<Vec<u32>> = Vec::new();
    let mut index_counter: i32 = 0;

    for start in 0..node_count {
        if dfn[start] != 0 { continue; }
        let mut dfs_stack: Vec<(u32, usize)> = Vec::new();
        let u = start as u32;
        index_counter += 1;
        dfn[start] = index_counter;
        low[start] = index_counter;
        stack.push(u);
        on_stack[start] = true;
        dfs_stack.push((u, 0));

        while let Some(&mut (v, ref mut ni)) = dfs_stack.last_mut() {
            let v_usize = v as usize;
            if *ni < edges[v_usize].len() {
                let w = edges[v_usize][*ni];
                *ni += 1;
                let w_usize = w as usize;
                if dfn[w_usize] == 0 {
                    index_counter += 1;
                    dfn[w_usize] = index_counter;
                    low[w_usize] = index_counter;
                    stack.push(w);
                    on_stack[w_usize] = true;
                    dfs_stack.push((w, 0));
                } else if on_stack[w_usize] && dfn[w_usize] < low[v_usize] {
                    low[v_usize] = dfn[w_usize];
                }
            } else {
                if low[v_usize] == dfn[v_usize] {
                    let mut scc: Vec<u32> = Vec::new();
                    loop {
                        let w = stack.pop().unwrap();
                        on_stack[w as usize] = false;
                        scc.push(w);
                        if w == v { break; }
                    }
                    scc.sort_unstable();
                    sccs.push(scc);
                }
                dfs_stack.pop();
                if let Some(&(parent, _)) = dfs_stack.last() {
                    let v_low = low[v_usize];
                    if v_low < low[parent as usize] {
                        low[parent as usize] = v_low;
                    }
                }
            }
        }
    }
    sccs.reverse();
    sccs
}

// =============================================================================
// Topological sort of SCCs
// =============================================================================

fn topological_sort_sccs_dense(
    sccs: &[Vec<u32>], edges: &[Vec<u32>], node_count: usize,
) -> Vec<usize> {
    let mut node_to_scc = vec![0usize; node_count];
    for (scc_idx, scc) in sccs.iter().enumerate() {
        for &node in scc { node_to_scc[node as usize] = scc_idx; }
    }

    let scc_n = sccs.len();
    let mut in_degree = vec![0usize; scc_n];
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); scc_n];
    let mut seen: Vec<HashSet<usize>> = vec![HashSet::new(); scc_n];

    for u in 0..node_count {
        let su = node_to_scc[u];
        for &v16 in &edges[u] {
            let sv = node_to_scc[v16 as usize];
            if su != sv && seen[su].insert(sv) {
                adj[su].push(sv);
                in_degree[sv] += 1;
            }
        }
    }

    let mut ready: VecDeque<usize> = VecDeque::new();
    let mut initial: Vec<usize> = (0..scc_n).filter(|&i| in_degree[i] == 0).collect();
    initial.sort_unstable();
    for s in initial { ready.push_back(s); }

    let mut result: Vec<usize> = Vec::with_capacity(scc_n);
    while let Some(s) = ready.pop_front() {
        result.push(s);
        let mut new_ready: Vec<usize> = Vec::new();
        for &v in &adj[s] {
            in_degree[v] -= 1;
            if in_degree[v] == 0 { new_ready.push(v); }
        }
        new_ready.sort_unstable();
        for v in new_ready { ready.push_back(v); }
    }
    result
}

// =============================================================================
// Hamiltonian Path
// =============================================================================

fn hamiltonian_path_dense(scc: &[u32], edges: &[Vec<u32>]) -> Vec<u32> {
    if scc.len() <= 1 { return scc.to_vec(); }

    let has_edge = |u: u32, v: u32| -> bool { edges[u as usize].contains(&v) };
    let mut sorted = scc.to_vec();
    sorted.sort_unstable();

    let mut path: VecDeque<u32> = VecDeque::new();
    path.push_back(sorted[0]);

    for &v in &sorted[1..] {
        if has_edge(v, *path.front().unwrap()) {
            path.push_front(v);
        } else if has_edge(*path.back().unwrap(), v) {
            path.push_back(v);
        } else {
            let mut inserted = false;
            for i in 0..path.len() - 1 {
                if has_edge(path[i], v) && has_edge(v, path[i + 1]) {
                    path.insert(i + 1, v);
                    inserted = true;
                    break;
                }
            }
            if !inserted {
                panic!("FATAL: Hamiltonian path insertion failed for node {} in SCC of size {}.", v, scc.len());
            }
        }
    }
    path.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_graph_grows_past_the_old_fixed_limit() {
        const OLD_FIXED_LIMIT: u32 = 16_384;
        let mut graph = DependencyGraph::new(7);

        for dense in 0..=OLD_FIXED_LIMIT {
            assert_eq!(graph.add_node(dense), dense);
        }

        assert_eq!(graph.node_count, OLD_FIXED_LIMIT as usize + 1);
        assert_eq!(graph.get_local(OLD_FIXED_LIMIT), Some(OLD_FIXED_LIMIT));
        assert_eq!(graph.edges.len(), graph.node_count);
    }

    #[test]
    fn pair_index_and_existing_edges_survive_graph_growth() {
        let mut graph = DependencyGraph::new(9);
        let first = graph.add_node(10);
        let second = graph.add_node(11);
        assert!(graph.add_edge(first, second));

        for dense in 12..20_000 {
            graph.add_node(dense);
        }

        assert!(graph.has_edge(first, second));
        assert!(!graph.add_edge(second, first));
        assert_eq!(graph.edge_pair_count, 1);
    }

    #[test]
    fn unresolved_pair_keeps_weights_until_later_observation_resolves_it() {
        let keys: Vec<PublicKey> = (0u8..5).map(|i| PublicKey([i; 32])).collect();
        let mut layer = FairnessLayer::new(keys, 1, 1.0);
        let first_dense = layer.get_or_create_dense(100);
        let second_dense = layer.get_or_create_dense(200);

        layer.nodes[first_dense as usize].committed_ois[0] = Some(1);
        layer.nodes[second_dense as usize].committed_ois[0] = Some(2);

        let mut graph = DependencyGraph::new(11);
        let first_local = graph.add_node(first_dense);
        let second_local = graph.add_node(second_dense);
        graph.missing_pairs.push(MissingPair::new(
            first_local,
            second_local,
            1,
            0,
            1,
        ));
        layer.graphs.push(graph);

        layer.nodes[first_dense as usize].committed_ois[1] = Some(3);
        layer.nodes[second_dense as usize].committed_ois[1] = Some(4);

        assert_eq!(layer.update_weights_and_edges(), (1, 1, 1));
        assert!(layer.graphs[0].missing_pairs.is_empty());
        assert!(layer.graphs[0].has_edge(first_local, second_local));
        assert_eq!(layer.graphs[0].edges[first_local as usize], vec![second_local]);
    }
}

# Copyright(C) Facebook, Inc. and its affiliates.
# Modified for FairDAG-RL v4: FairDAG metrics parsed from worker logs.
from datetime import datetime
from glob import glob
from multiprocessing import Pool
from os.path import join
from re import findall, search
from statistics import mean
from collections import defaultdict
import random
import os

from benchmark.utils import Print


def _to_posix(string):
    x = datetime.fromisoformat(string.replace('Z', '+00:00'))
    return datetime.timestamp(x)


class ParseError(Exception):
    pass


class LogParser:
    def __init__(
        self,
        clients,
        primaries,
        workers,
        attack_type=10,
        arbitragers=1,
        faults=0,
        input_rate=None,
    ):
        inputs = [clients, primaries, workers]
        assert all(isinstance(x, list) for x in inputs)
        assert all(isinstance(x, str) for y in inputs for x in y)
        assert all(x for x in inputs)

        self.attack_type = attack_type
        self.arbitragers = arbitragers
        self.faults = faults
        if isinstance(faults, int):
            self.committee_size = len(primaries)
            self.workers = len(workers) // len(primaries)
        else:
            self.committee_size = '?'
            self.workers = '?'

        # Parse the clients logs.
        try:
            with Pool() as p:
                results = p.map(self._parse_clients, clients)
        except (ValueError, IndexError, AttributeError) as e:
            raise ParseError(f'Failed to parse clients\' logs: {e}')
        self.size, self.rate, self.start, misses, self.sent_samples \
            = zip(*results)
        self.misses = sum(misses)
        self.input_rate = input_rate if input_rate is not None else sum(self.rate)

        self.all_sent_samples = {}
        for samples in self.sent_samples:
            for tx_id, send_time in samples.items():
                if tx_id in self.all_sent_samples:
                    raise ParseError(
                        f'Duplicate sample transaction id {tx_id} across clients; '
                        'latency matching would be ambiguous'
                    )
                self.all_sent_samples[tx_id] = send_time

        # Parse the primaries logs.
        try:
            with Pool() as p:
                results = p.map(self._parse_primaries, primaries)
        except (ValueError, IndexError, AttributeError) as e:
            raise ParseError(f'Failed to parse nodes\' logs: {e}')
        (proposals, commits, self.configs, primary_ips, blocks_to_heights,
         monitor_attacks, fissure_attacks, sluggish_attacks, speculative_attacks,
        ) = zip(*results)
        self.proposals = self._merge_results([x.items() for x in proposals])
        self.commits = self._merge_results([x.items() for x in commits])
        self.blocks_to_heights = self._merge_blocks_to_heights([x.items() for x in blocks_to_heights])
        self.monitor_attacks = self._merge_monitor([x.items() for x in monitor_attacks])
        self.fissure_attacks = self._merge_frontrun_attack([x.items() for x in fissure_attacks])
        self.sluggish_attacks = self._merge_frontrun_attack([x.items() for x in sluggish_attacks])
        self.speculative_attacks = self._merge_frontrun_attack([x.items() for x in speculative_attacks])

        # Parse the workers logs.
        try:
            with Pool() as p:
                results = p.map(self._parse_workers, workers)
        except (ValueError, IndexError, AttributeError) as e:
            raise ParseError(f'Failed to parse workers\' logs: {e}')
        sizes, self.received_samples, workers_ips, fair_ordered_txs_list, fair_ordered_seqs_list, fair_graph_stats_list, arrival_times_list, task_timings_list = zip(*results)
        self.sizes = {k: v for x in sizes for k, v in x.items() if k in self.commits}
        self.all_received_samples = self._merge_dicts(self.received_samples)

        self.fair_ordered_txs = self._merge_results([x.items() for x in fair_ordered_txs_list])
        if not self.fair_ordered_txs:
            Print.warn(
                'No FairDAG-RL final-order records found; final-order throughput '
                'and latency will be zero'
            )
        elif not set(self.fair_ordered_txs).intersection(self.all_sent_samples):
            Print.warn('No client sample transaction matched a FairDAG-RL final-order record')

        # Aggregate per-task CPU timings across all workers.
        # Each worker contributes its own list of samples per task name.
        self.task_timings = defaultdict(list)
        for d in task_timings_list:
            for name, samples in d.items():
                self.task_timings[name].extend(samples)
        self.task_timings = dict(self.task_timings)

        # Protocol's final ordering (position in log, not timestamp).
        # Take from first worker that has it (all workers finalize same order).
        self.fair_ordered_seqs = {}
        for seqs in fair_ordered_seqs_list:
            if seqs and not self.fair_ordered_seqs:
                self.fair_ordered_seqs = seqs

        self.fair_graph_stats = []
        for stats_list in fair_graph_stats_list:
            self.fair_graph_stats.extend(stats_list)

        # Adversarial reordering: build per-NODE arrival times.
        workers_per_node = self.workers if isinstance(self.workers, int) else 1
        n_nodes = self.committee_size if isinstance(self.committee_size, int) else len(primaries)
        self.per_node_arrivals = []
        for node_idx in range(n_nodes):
            node_arrivals = {}
            for w_offset in range(workers_per_node):
                w_idx = node_idx * workers_per_node + w_offset
                if w_idx < len(arrival_times_list):
                    for tx_uid, t in arrival_times_list[w_idx].items():
                        if tx_uid not in node_arrivals or t < node_arrivals[tx_uid]:
                            node_arrivals[tx_uid] = t
            self.per_node_arrivals.append(node_arrivals)

        self.collocate = set(primary_ips) == set(workers_ips)
        if self.misses != 0:
            Print.warn(f'Clients missed their target rate {self.misses:,} time(s)')

    # ---- Merge helpers ----

    @staticmethod
    def _merge_dicts(input):
        merged_dict = defaultdict(list)
        for d in input:
            for k, v in d.items():
                merged_dict[k].append(v)
        return dict(merged_dict)

    @staticmethod
    def _merge_results(input):
        merged = {}
        for x in input:
            for k, v in x:
                if k not in merged or merged[k] > v:
                    merged[k] = v
        return merged

    @staticmethod
    def _merge_blocks_to_heights(input):
        merged = {}
        for x in input:
            for block, height in x:
                if block not in merged:
                    merged[block] = int(height)
        return merged

    @staticmethod
    def _merge_monitor(input):
        merged = {}
        for x in input:
            for victim_header, attack_header in x:
                if victim_header not in merged:
                    merged[victim_header] = attack_header
        return merged

    @staticmethod
    def _merge_frontrun_attack(input):
        merged = {}
        for x in input:
            for victim_header, attack_header in x:
                if victim_header not in merged:
                    merged[victim_header] = attack_header
        return merged

    # ---- Log parsers ----

    def _parse_clients(self, log):
        if search(r"(?:panicked|Error)", log) is not None:
            raise ParseError('Client(s) panicked')
        size = int(search(r"Transactions size: (\d+)", log).group(1))
        rate = int(search(r"Transactions rate: (\d+)", log).group(1))
        tmp = search(r"\[(.*Z) .* Start ", log).group(1)
        start = _to_posix(tmp)
        misses = len(findall(r"rate too high", log))
        tmp = findall(r"\[(.*Z) .* Sending sample transaction (\d+)", log)
        samples = {int(s): _to_posix(t) for t, s in tmp}
        return size, rate, start, misses, samples

    def _parse_primaries(self, log):
        if search(r"(?:panicked|Error)", log) is not None:
            raise ParseError('Primary(s) panicked')
        tmp = findall(r"\[(.*Z) .* Created B\d+\([^ ]+\) -> ([^ ]+=)", log)
        tmp = [(d, _to_posix(t)) for t, d in tmp]
        proposals = self._merge_results([tmp])
        tmp = findall(r"\[(.*Z) .* Committed B\d+\([^ ]+\) -> ([^ ]+=)", log)
        tmp = [(d, _to_posix(t)) for t, d in tmp]
        commits = self._merge_results([tmp])
        tmp = findall(r"\[(.*Z) .* FairDag Committed ([^ ]+) in height (\d+)", log)
        tmp = [(header, height) for t, header, height in tmp]
        blocks_to_heights = self._merge_blocks_to_heights([tmp])
        tmp = findall(r"\[(.*Z) .* FairDag Monitor attacking header ([^ ]+), victim header ([^ ]+), in round (\d+)", log)
        tmp = [(victim_header, attack_header) for t, attack_header, victim_header, round in tmp]
        monitor_attacks = self._merge_monitor([tmp])
        tmp = findall(r"\[(.*Z) .* FairDag Created a fissure attacking header ([^ ]+), victim header ([^ ]+), in round (\d+)", log)
        tmp = [(victim_header, attack_header) for t, attack_header, victim_header, round in tmp]
        fissure_attacks = self._merge_frontrun_attack([tmp])
        tmp = findall(r"\[(.*Z) .* FairDag Created a sluggish attacking header ([^ ]+), victim header ([^ ]+), in round (\d+)", log)
        tmp = [(victim_header, attack_header) for t, attack_header, victim_header, round in tmp]
        sluggish_attacks = self._merge_frontrun_attack([tmp])
        tmp = findall(r"\[(.*Z) .* FairDag Created a speculative attacking header ([^ ]+), victim header ([^ ]+), in round (\d+)", log)
        tmp = [(victim_header, attack_header) for t, attack_header, victim_header, round in tmp]
        speculative_attacks = self._merge_frontrun_attack([tmp])
        configs = {
            "header_size": int(search(r"Header size .* (\d+)", log).group(1)),
            "max_header_delay": int(search(r"Max header delay .* (\d+)", log).group(1)),
            "gc_depth": int(search(r"Garbage collection depth .* (\d+)", log).group(1)),
            "sync_retry_delay": int(search(r"Sync retry delay .* (\d+)", log).group(1)),
            "sync_retry_nodes": int(search(r"Sync retry nodes .* (\d+)", log).group(1)),
            "batch_size": int(search(r"Batch size .* (\d+)", log).group(1)),
            "max_batch_delay": int(search(r"Max batch delay .* (\d+)", log).group(1)),
        }
        ip = search(r"booted on (\d+.\d+.\d+.\d+)", log).group(1)
        return (proposals, commits, configs, ip, blocks_to_heights,
                monitor_attacks, fissure_attacks, sluggish_attacks, speculative_attacks)

    def _parse_workers(self, log):
        if search(r"(?:panicked|Error)", log) is not None:
            raise ParseError('Worker(s) panicked')
        tmp = findall(r"Batch ([^ ]+) contains (\d+) B", log)
        sizes = {d: int(s) for d, s in tmp}
        tmp = findall(r"Batch ([^ ]+) contains tx (\d+)", log)
        samples = {int(s): d for d, s in tmp}
        ip = search(r"booted on (\d+.\d+.\d+.\d+)", log).group(1)

        tmp = findall(r"\[(.*Z) .* FairDAG-RL ordered transaction: (\d+)", log)
        fair_ordered_txs = self._merge_results([
            [(int(tx_id), _to_posix(t)) for t, tx_id in tmp]
        ])
        # Position in log = protocol's final order (no timestamp needed)
        fair_ordered_seqs = {}
        for pos, (t, tx_id) in enumerate(tmp):
            tx = int(tx_id)
            if tx not in fair_ordered_seqs:
                fair_ordered_seqs[tx] = pos

        fair_graph_stats = []
        tmp_old = findall(r"\[(.*Z) .* FairnessLayer: finalized (\d+) transactions from graph (\d+) \(round (\d+)\)\. Total ordered: (\d+)", log)
        for t, num_txs, graph_idx, round_num, total in tmp_old:
            fair_graph_stats.append({'timestamp': _to_posix(t), 'num_txs': int(num_txs), 'graph_idx': int(graph_idx), 'round': int(round_num), 'total_ordered': int(total)})
        tmp_new = findall(r"\[(.*Z) .* FairDAG: FINALIZED sub_dag_id=(\d+), (\d+) transactions", log)
        for t, sub_dag_id, num_txs in tmp_new:
            fair_graph_stats.append({'timestamp': _to_posix(t), 'num_txs': int(num_txs), 'graph_idx': int(sub_dag_id), 'round': 0, 'total_ordered': 0})

        tmp = findall(r'\[(.*Z) .* fairness_arrival tx_uid=(\d+) oi=(\d+)', log)
        arrival_times = {int(tx_uid): _to_posix(t) for t, tx_uid, oi in tmp}

        # Per-task CPU timings: FAIRDAG_TASK: name=<task> us=<microseconds>
        # Collect per-worker as a dict task_name -> list of microsecond samples.
        task_timings = defaultdict(list)
        for name, us in findall(r"FAIRDAG_TASK: name=(\w+) us=(\d+)", log):
            task_timings[name].append(int(us))
        task_timings = dict(task_timings)

        return sizes, samples, ip, fair_ordered_txs, fair_ordered_seqs, fair_graph_stats, arrival_times, task_timings

    # ---- Attack results ----

    def _attack_results(self, attack_dict):
        attack_num = 0; succ_num = 0
        for victim_header, attacking_header in attack_dict.items():
            if victim_header in self.blocks_to_heights and attacking_header in self.blocks_to_heights:
                attack_num += 1
                if self.blocks_to_heights[victim_header] > self.blocks_to_heights[attacking_header]:
                    succ_num += 1
        return succ_num, attack_num
    def _attack_monitor_results(self): return self._attack_results(self.monitor_attacks)
    def _fissure_attack_results(self): return self._attack_results(self.fissure_attacks)
    def _sluggish_attack_results(self): return self._attack_results(self.sluggish_attacks)
    def _speculative_attack_results(self): return self._attack_results(self.speculative_attacks)

    # ---- Throughput & latency ----

    def _committed_tx_stats(self):
        committed_count = 0; latencies = []
        for tx_id, batch_ids in self.all_received_samples.items():
            if tx_id not in self.all_sent_samples: continue
            send_time = self.all_sent_samples[tx_id]
            commit_times = [self.commits[b] for b in batch_ids if b in self.commits]
            if commit_times:
                committed_count += 1
                latencies.append(min(commit_times) - send_time)
        return committed_count, latencies

    def _consensus_throughput(self):
        if not self.commits or not self.proposals: return 0, 0, 0
        start = min(self.proposals.values()); end = max(self.commits.values())
        duration = end - start
        if duration <= 0: return 0, 0, 0
        committed_bytes = sum(self.sizes[d] for d in self.commits if d in self.sizes)
        bps = committed_bytes / duration
        tps = bps / self.size[0]
        return tps, bps, duration

    def _consensus_latency(self):
        latency = [commit_time - self.proposals[bd] for bd, commit_time in self.commits.items() if bd in self.proposals]
        return mean(latency) if latency else 0

    # ---- FairDAG-RL metrics ----

    def _fairdag_tx_stats(self):
        latencies = []
        for tx_id, fair_time in self.fair_ordered_txs.items():
            if tx_id not in self.all_sent_samples: continue
            latencies.append(fair_time - self.all_sent_samples[tx_id])
        return len(self.fair_ordered_txs), latencies

    def _fairdag_throughput(self):
        if not self.fair_ordered_txs: return 0, 0, 0
        start = min(self.start); end = max(self.fair_ordered_txs.values()); duration = end - start
        if duration <= 0: return 0, 0, 0
        fair_count, _ = self._fairdag_tx_stats()
        return fair_count / duration, (fair_count / duration) * self.size[0], duration

    def _fairdag_latency(self):
        _, latencies = self._fairdag_tx_stats()
        return mean(latencies) if latencies else 0

    def _fairdag_finalization_overhead(self):
        overheads = []
        for tx_id, fair_time in self.fair_ordered_txs.items():
            if tx_id not in self.all_received_samples: continue
            commit_times = [self.commits[b] for b in self.all_received_samples[tx_id] if b in self.commits]
            if commit_times: overheads.append(fair_time - min(commit_times))
        return mean(overheads) if overheads else 0

    def _fairdag_graph_summary(self):
        if not self.fair_graph_stats: return 0, 0, 0
        txs_per_graph = [s['num_txs'] for s in self.fair_graph_stats]
        max_total = max((s['total_ordered'] for s in self.fair_graph_stats), default=0)
        total_ordered = max_total if max_total > 0 else sum(txs_per_graph)
        return len(self.fair_graph_stats), mean(txs_per_graph) if txs_per_graph else 0, total_ordered

    def _end_to_end_throughput(self):
        # Keep MRV's aggregation label, but this endpoint is FairDAG final-order
        # completion (not Narwhal/Tusk commit or application execution/reply).
        if not self.fair_ordered_txs: return 0, 0, 0
        return self._fairdag_throughput()
    def _end_to_end_latency(self):
        return self._fairdag_latency()

    def _task_timings_summary(self):
        """
        Per-task CPU time aggregation across all workers.

        Returns a list of (task_name, avg_us, p50_us, p99_us, count) tuples
        sorted by descending mean. Times are in microseconds. Returns empty
        list if no FAIRDAG_TASK lines were emitted.
        """
        if not self.task_timings:
            return []
        from statistics import median
        rows = []
        for name, samples in self.task_timings.items():
            if not samples:
                continue
            n = len(samples)
            samples_sorted = sorted(samples)
            avg = sum(samples) / n
            p50 = median(samples)
            p99 = samples_sorted[min(n - 1, int(0.99 * n))]
            rows.append((name, avg, p50, p99, n))
        rows.sort(key=lambda r: -r[1])
        return rows

    # ------------------------------------------------------------------
    # Adversarial reordering: Dist(tx,tx') vs fraction reversed
    # ------------------------------------------------------------------

    def _adversarial_reordering(self):
        """
        ALL-PAIRS adversarial reordering via Rust binary (adv_reorder).
        Falls back to Python if binary not found.
        """
        import subprocess, json, shutil

        N = self.committee_size
        if not isinstance(N, int) or N < 2: return None

        f = self.faults if isinstance(self.faults, int) else 0

        return None

        # Find the Rust binary
        binary = shutil.which('adv_reorder')
        if binary is None:
            # Try common locations
            for candidate in ['./adv_reorder', '../adv_reorder/target/release/adv_reorder']:
                if os.path.isfile(candidate):
                    binary = candidate
                    break
        if binary is None:
            print("  WARN: adv_reorder binary not found, skipping reordering metric")
            return None

        # Find logs directory
        logs_dir = getattr(self, 'logs_dir', None)
        if logs_dir is None:
            for candidate in ['logs']:
                if os.path.isdir(candidate):
                    logs_dir = candidate
                    break
        if logs_dir is None:
            print("  WARN: logs directory not found")
            return None

        cmd = [
            binary,
            '-d', logs_dir,
            '-n', str(N),
            '-f', str(f),
            '--verbose',
        ]
        print(f"  Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode != 0:
                print(f"  WARN: adv_reorder failed: {result.stderr[:500]}")
                return None

            data = json.loads(result.stdout)

            # Convert JSON to our dict format
            start_dist = N % 2
            dist_values = list(range(start_dist, N + 1, 2))
            results = {d: (0.0, 0) for d in dist_values}
            for entry in data.get('results', []):
                d = entry['dist']
                if d in results:
                    results[d] = (entry['fraction_reversed'], entry['count'])

            return results

        except subprocess.TimeoutExpired:
            print("  WARN: adv_reorder timed out (600s)")
            return None
        except (json.JSONDecodeError, KeyError) as e:
            print(f"  WARN: Failed to parse adv_reorder output: {e}")
            return None

    # ---- Output ----

    def result(self):
        header_size = self.configs[0]['header_size']
        max_header_delay = self.configs[0]['max_header_delay']
        gc_depth = self.configs[0]['gc_depth']
        sync_retry_delay = self.configs[0]['sync_retry_delay']
        sync_retry_nodes = self.configs[0]['sync_retry_nodes']
        batch_size = self.configs[0]['batch_size']
        max_batch_delay = self.configs[0]['max_batch_delay']
        consensus_latency = self._consensus_latency() * 1_000
        consensus_tps, consensus_bps, _ = self._consensus_throughput()
        end_to_end_tps, end_to_end_bps, duration = self._end_to_end_throughput()
        end_to_end_latency = self._end_to_end_latency() * 1_000
        fairdag_overhead = self._fairdag_finalization_overhead() * 1_000
        fairdag_count, fairdag_latencies = self._fairdag_tx_stats()
        num_graphs, avg_txs_per_graph, total_fair_ordered = self._fairdag_graph_summary()
        attack_print = ""
        ms, mt = self._attack_monitor_results(); fs, ft = self._fissure_attack_results()
        ss, st = self._sluggish_attack_results(); sps, spt = self._speculative_attack_results()
        if mt != 0: attack_print = f"Baseline front-running rate: {round(ms/mt*100, 2):,}% ({ms:,}/{mt:,})"
        elif ft != 0: attack_print = f"Fissure front-running rate: {round(fs/ft*100, 2):,}% ({fs:,}/{ft:,})"
        elif st != 0: attack_print = f"Sluggish front-running rate: {round(ss/st*100, 2):,}% ({ss:,}/{st:,})"
        elif spt != 0: attack_print = f"Speculative front-running rate: {round(sps/spt*100, 2):,}% ({sps:,}/{spt:,})"
        reorder_results = self._adversarial_reordering()
        reorder_print = ""
        if reorder_results:
            reorder_print = '\n + ADVERSARIAL REORDERING (Dist -> fraction reversed):\n'
            for d in sorted(reorder_results.keys()):
                frac, count = reorder_results[d]
                reorder_print += f'   Dist={d:3d}: {frac:.4f}  ({count:,} pairs)\n'

        task_print = ""
        task_rows = self._task_timings_summary()
        if task_rows:
            task_print = '\n + PER-TASK CPU TIME (microseconds, aggregated across workers):\n'
            task_print += f'   {"task":<14} {"avg":>10} {"p50":>10} {"p99":>10} {"samples":>10}\n'
            for name, avg, p50, p99, n in task_rows:
                task_print += f'   {name:<14} {avg:>10.1f} {p50:>10.1f} {p99:>10.1f} {n:>10,}\n'
        return (
            '\n-----------------------------------------\n SUMMARY:\n-----------------------------------------\n'
            ' + CONFIG:\n'
            f' Faults: {self.faults} node(s)\n'
            f' Committee size: {self.committee_size} node(s)\n'
            f' Worker(s) per node: {self.workers} worker(s)\n'
            f' Collocate primary and workers: {self.collocate}\n'
            f' Input rate: {self.input_rate:,} tx/s\n'
            f' Transaction size: {self.size[0]:,} B\n'
            f' Execution time: {round(duration):,} s\n\n'
            f' Header size: {header_size:,} B\n'
            f' Max header delay: {max_header_delay:,} ms\n'
            f' GC depth: {gc_depth:,} round(s)\n'
            f' Sync retry delay: {sync_retry_delay:,} ms\n'
            f' Sync retry nodes: {sync_retry_nodes:,} node(s)\n'
            f' batch size: {batch_size:,} B\n'
            f' Max batch delay: {max_batch_delay:,} ms\n\n'
            ' + RESULTS:\n'
            f' Consensus TPS: {round(consensus_tps):,} tx/s\n'
            f' Consensus BPS: {round(consensus_bps):,} B/s\n'
            f' Consensus latency: {round(consensus_latency):,} ms\n\n'
            ' + FAIRDAG-RL:\n'
            f' End-to-end TPS: {round(end_to_end_tps):,} tx/s\n'
            f' End-to-end BPS: {round(end_to_end_bps):,} B/s\n'
            f' End-to-end latency: {round(end_to_end_latency):,} ms\n'
            f' End-to-end latency samples: {len(fairdag_latencies):,}\n'
            f' Fair ordering overhead: {round(fairdag_overhead):,} ms\n'
            f' Fair-ordered txs: {fairdag_count:,}\n'
            f' Graphs finalized: {num_graphs:,}\n'
            f' Avg txs/graph: {round(avg_txs_per_graph, 1)}\n'
            f' Total fair-ordered (from logs): {total_fair_ordered:,}\n\n'
            f' + ATTACK:\n {attack_print} \n'
            f'{reorder_print}'
            f'{task_print}'
            '-----------------------------------------\n')

    def print(self, filename):
        with open(filename, 'a') as f: f.write(self.result())

    @classmethod
    def process(
        cls,
        directory,
        attack_type=10,
        arbitragers=1,
        faults=0,
        input_rate=None,
    ):
        clients = [open(fn).read() for fn in sorted(glob(join(directory, "client-*.log")))]
        primaries = [open(fn).read() for fn in sorted(glob(join(directory, "primary-*.log")))]
        workers = [open(fn).read() for fn in sorted(glob(join(directory, "worker-*.log")))]
        instance = cls(
            clients,
            primaries,
            workers,
            attack_type=attack_type,
            arbitragers=arbitragers,
            faults=faults,
            input_rate=input_rate,
        )
        instance.logs_dir = directory
        return instance

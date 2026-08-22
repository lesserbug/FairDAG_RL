import unittest
from collections import OrderedDict
from unittest.mock import patch

from benchmark.commands import CommandMaker
from benchmark.config import BenchParameters, Committee, ConfigError, NodeParameters
from benchmark.logs import LogParser, ParseError, _to_posix
from benchmark.utils import (
    PathMaker,
    distribute_client_rates,
    validate_crash_faults,
)


def client_log(start, samples=(), misses=0):
    lines = [
        'Transactions size: 512 B',
        'Transactions rate: 100 tx/s',
        f'[{start} INFO benchmark_client] Start sending transactions',
    ]
    lines.extend(
        f'[{timestamp} INFO benchmark_client] Sending sample transaction {tx_id}'
        for timestamp, tx_id in samples
    )
    lines.extend(
        '[2026-01-01T00:00:03.000Z WARN benchmark_client] '
        'Transaction rate too high for this client'
        for _ in range(misses)
    )
    return '\n'.join(lines)


def primary_log(ip):
    return '\n'.join([
        'Header size set to 1000 B',
        'Max header delay set to 200 ms',
        'Garbage collection depth set to 50 rounds',
        'Sync retry delay set to 10000 ms',
        'Sync retry nodes set to 3 nodes',
        'Batch size set to 500000 B',
        'Max batch delay set to 200 ms',
        f'Primary successfully booted on {ip}',
        '[2026-01-01T00:00:04.000Z INFO node] Created B1(node) -> batch=',
        '[2026-01-01T00:00:05.000Z INFO node] Committed B1(node) -> batch=',
    ])


def worker_log(ip, final_orders=()):
    lines = [
        f'Worker 0 successfully booted on {ip}',
        'Batch batch= contains 512 B',
    ]
    lines.extend(
        f'[{timestamp} INFO worker] FairDAG-RL ordered transaction: {tx_id}'
        for timestamp, tx_id in final_orders
    )
    return '\n'.join(lines)


class FinalOrderLogTests(unittest.TestCase):
    def test_final_order_deduplication_window_and_latency(self):
        clients = [
            client_log(
                '2026-01-01T00:00:00.000Z',
                [('2026-01-01T00:00:01.000Z', 101)],
            ),
            client_log(
                '2026-01-01T00:00:00.500Z',
                [('2026-01-01T00:00:02.000Z', 202)],
                misses=1,
            ),
        ]
        primaries = [primary_log('10.0.0.1'), primary_log('10.0.0.2')]
        workers = [
            worker_log('10.0.0.1', [
                ('2026-01-01T00:00:10.000Z', 101),
                ('2026-01-01T00:00:11.000Z', 101),
                ('2026-01-01T00:00:12.000Z', 202),
            ]),
            worker_log('10.0.0.2', [
                ('2026-01-01T00:00:09.000Z', 101),
                ('2026-01-01T00:01:05.000Z', 303),
            ]),
        ]

        with patch('benchmark.logs.Print.warn') as warn:
            parser = LogParser(clients, primaries, workers, faults=0)

        self.assertEqual(len(parser.fair_ordered_txs), 3)
        self.assertEqual(
            parser.fair_ordered_txs[101],
            _to_posix('2026-01-01T00:00:09.000Z'),
        )
        tps, _, duration = parser._end_to_end_throughput()
        self.assertEqual(duration, 65.0)
        self.assertAlmostEqual(tps, 3 / 65.0)
        self.assertEqual(parser._end_to_end_latency(), 9.0)
        self.assertEqual(len(parser._fairdag_tx_stats()[1]), 2)
        self.assertEqual(parser.misses, 1)
        self.assertTrue(any('missed their target rate' in str(call) for call in warn.call_args_list))

        result = parser.result()
        self.assertIn('End-to-end latency: 9,000 ms', result)
        self.assertIn('End-to-end latency samples: 2', result)

    def test_unmatched_samples_are_not_filled_with_zero(self):
        parser = LogParser(
            [client_log(
                '2026-01-01T00:00:00.000Z',
                [('2026-01-01T00:00:01.000Z', 999)],
            )],
            [primary_log('10.0.0.1')],
            [worker_log('10.0.0.1', [
                ('2026-01-01T00:00:05.000Z', 123),
            ])],
            faults=0,
        )
        self.assertEqual(parser._end_to_end_latency(), 0)
        self.assertEqual(len(parser._fairdag_tx_stats()[1]), 0)
        self.assertIn('End-to-end latency samples: 0', parser.result())

    def test_missing_final_order_records_return_zero(self):
        with patch('benchmark.logs.Print.warn') as warn:
            parser = LogParser(
                [client_log('2026-01-01T00:00:00.000Z')],
                [primary_log('10.0.0.1')],
                [worker_log('10.0.0.1')],
                faults=0,
            )
        self.assertEqual(parser._end_to_end_throughput(), (0, 0, 0))
        self.assertEqual(parser._end_to_end_latency(), 0)
        self.assertTrue(any('No FairDAG-RL final-order records' in str(call) for call in warn.call_args_list))

    def test_duplicate_client_sample_id_is_rejected(self):
        duplicate = [('2026-01-01T00:00:01.000Z', 77)]
        with self.assertRaisesRegex(ParseError, 'Duplicate sample transaction id 77'):
            LogParser(
                [
                    client_log('2026-01-01T00:00:00.000Z', duplicate),
                    client_log('2026-01-01T00:00:00.000Z', duplicate),
                ],
                [primary_log('10.0.0.1'), primary_log('10.0.0.2')],
                [worker_log('10.0.0.1'), worker_log('10.0.0.2')],
                faults=0,
            )


class BenchmarkConfigurationTests(unittest.TestCase):
    def test_fault_runs_preserve_the_exact_total_offered_rate(self):
        for active_clients in (10, 9, 8):
            rates = distribute_client_rates(3_000, active_clients)
            self.assertEqual(sum(rates), 3_000)
            self.assertEqual(len(rates), active_clients)
            self.assertTrue(all(rate % 20 == 0 for rate in rates))
            self.assertLessEqual(max(rates) - min(rates), 20)

    def test_client_rate_distribution_rejects_fractional_bursts(self):
        with self.assertRaisesRegex(ValueError, 'positive multiple of 20'):
            distribute_client_rates(3_001, 9)

    def test_crashes_above_the_configured_threshold_are_rejected(self):
        validate_crash_faults(2, 2, [10])
        with self.assertRaisesRegex(ValueError, 'Crash faults=3'):
            validate_crash_faults(3, 2, [10])

    def test_remote_result_identity_includes_batch_size(self):
        filename = PathMaker.result_file(0, 0, 1, 1, 10, 51_200)
        self.assertTrue(filename.endswith('remote-0-0-1-1-10-b51200.txt'))

    def test_drain_duration_defaults_to_zero_and_rejects_negative_values(self):
        base = {
            'faults': 0,
            'arbitragers': 0,
            'attack_type': 0,
            'nodes': [5],
            'workers': 1,
            'rate': [20_000],
            'tx_size': 512,
            'duration': 60,
        }
        self.assertEqual(BenchParameters(base).drain_duration, 0)
        with self.assertRaisesRegex(ConfigError, 'Drain duration'):
            BenchParameters({**base, 'drain_duration': -1})

    def test_honest_remote_committee_writes_required_attack_type(self):
        addresses = OrderedDict([
            ('node-a', ['10.0.0.1', '10.0.0.1']),
            ('node-b', ['10.0.0.2', '10.0.0.2']),
        ])
        committee = Committee(addresses, 5000)
        self.assertTrue(all(
            authority['attack_type'] == 0
            for authority in committee.json['authorities'].values()
        ))

    def test_fairdag_node_parameters_required_by_remote_are_valid(self):
        parameters = NodeParameters({
            'header_size': 1_000,
            'max_header_delay': 200,
            'gc_depth': 50,
            'sync_retry_delay': 10_000,
            'sync_retry_nodes': 3,
            'batch_size': 500_000,
            'max_batch_delay': 200,
            'gamma': 1.0,
            'scc_ordering': 'alphabetical',
            'fault_threshold': 1,
        })
        self.assertEqual(parameters.json['batch_size'], 500_000)

    def test_client_command_carries_the_client_namespace(self):
        command = CommandMaker.run_client(
            '127.0.0.1:5000',
            512,
            4_000,
            ['127.0.0.1:5000'],
            7,
        )
        self.assertIn('--client-id 7', command)


if __name__ == '__main__':
    unittest.main()

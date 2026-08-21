# Copyright(C) Facebook, Inc. and its affiliates.
import subprocess
from math import ceil
from os.path import basename, splitext
from time import sleep

from benchmark.commands import CommandMaker
from benchmark.config import (
    Key,
    LocalCommittee,
    NodeParameters,
    BenchParameters,
    ConfigError,
)
from benchmark.logs import LogParser, ParseError
from benchmark.utils import Print, BenchError, PathMaker


class LocalBench:
    BASE_PORT = 4000

    def __init__(self, bench_parameters_dict, node_parameters_dict):
        try:
            self.bench_parameters = BenchParameters(bench_parameters_dict)
            self.node_parameters = NodeParameters(node_parameters_dict)
        except ConfigError as e:
            raise BenchError("Invalid nodes or bench parameters", e)

    def __getattr__(self, attr):
        return getattr(self.bench_parameters, attr)

    def _background_run(self, command, log_file):
        name = splitext(basename(log_file))[0]
        cmd = f"{command} 2> {log_file}"
        subprocess.run(["tmux", "new", "-d", "-s", name, cmd], check=True)

    def _kill_nodes(self):
        try:
            subprocess.run(
                CommandMaker.kill_nodes(),
                shell=True,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.SubprocessError as e:
            raise BenchError("Failed to kill testbed", e)

    def _kill_clients(self):
        try:
            subprocess.run(
                CommandMaker.kill_clients(),
                shell=True,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.SubprocessError as e:
            raise BenchError("Failed to kill clients", e)

    def run(self, debug=False):
        assert isinstance(debug, bool)
        Print.heading("Starting local benchmark")

        # Kill any previous testbed.
        self._kill_clients()
        self._kill_nodes()

        try:
            Print.info("Setting up testbed...")
            nodes, rate = self.nodes[0], self.rate[0]
            arbitragers = self.arbitragers
            attack_type = self.attack_type

            # Cleanup all files.
            cmd = f"{CommandMaker.clean_logs()} ; {CommandMaker.cleanup()}"
            subprocess.run([cmd], shell=True, stderr=subprocess.DEVNULL)
            sleep(0.5)  # Removing the store may take time.

            # Recompile the latest code.
            cmd = CommandMaker.compile().split()
            subprocess.run(cmd, check=True, cwd=PathMaker.node_crate_path())

            # Create alias for the client and nodes binary.
            cmd = CommandMaker.alias_binaries(PathMaker.binary_path())
            subprocess.run([cmd], shell=True)

            # Generate configuration files.
            keys = []
            key_files = [PathMaker.key_file(i) for i in range(nodes)]
            for filename in key_files:
                cmd = CommandMaker.generate_key(filename).split()
                subprocess.run(cmd, check=True)
                keys += [Key.from_file(filename)]

            names = [x.name for x in keys]
            committee = LocalCommittee(
                names, 
                self.BASE_PORT, 
                self.workers,
                self.faults,
                arbitragers,
                attack_type,
            )
            committee.print(PathMaker.committee_file())

            self.node_parameters.print(PathMaker.parameters_file())

            # Run the clients (they will wait for the nodes to be ready).
            workers_addresses = committee.workers_addresses(self.faults)
            rate_share = ceil(rate / committee.workers())

            all_worker_addresses = [
                address
                for authority in workers_addresses
                for _, address in authority
            ]
            client_id = 0
            for i, addresses in enumerate(workers_addresses):
                for id, address in addresses:
                    cmd = CommandMaker.run_client(
                        address,
                        self.tx_size,
                        rate_share,
                        all_worker_addresses,
                        client_id,
                    )
                    log_file = PathMaker.client_log_file(i, id)
                    self._background_run(cmd, log_file)
                    client_id += 1

            # Run the primaries (except the faulty ones).
            for i, address in enumerate(committee.primary_addresses(self.faults)):
                cmd = CommandMaker.run_primary(
                    PathMaker.key_file(i),
                    PathMaker.committee_file(),
                    PathMaker.db_path(i),
                    PathMaker.parameters_file(),
                    debug=debug,
                )
                log_file = PathMaker.primary_log_file(i)
                self._background_run(cmd, log_file)

            # Run the workers (except the faulty ones).
            for i, addresses in enumerate(workers_addresses):
                for id, address in addresses:
                    cmd = CommandMaker.run_worker(
                        PathMaker.key_file(i),
                        PathMaker.committee_file(),
                        PathMaker.db_path(i, id),
                        PathMaker.parameters_file(),
                        id,  # The worker's id.
                        debug=debug,
                    )
                    log_file = PathMaker.worker_log_file(i, id)
                    self._background_run(cmd, log_file)

            # Wait for all transactions to be processed.
            Print.info(f"Running benchmark ({self.duration} sec)...")
            sleep(self.duration)

            Print.info(
                f"Stopping clients and draining benchmark ({self.drain_duration} sec)..."
            )
            self._kill_clients()
            if self.drain_duration > 0:
                sleep(self.drain_duration)
            else:
                Print.warn(
                    'drain_duration is 0; FairDAG final ordering may be right-censored'
                )
            self._kill_nodes()

            # Parse logs and return the parser.
            Print.info("Parsing logs...")
            return LogParser.process(
                PathMaker.logs_path(), 
                attack_type=attack_type,
                arbitragers=arbitragers,
                faults=self.faults,
                input_rate=rate,
            )

        except (subprocess.SubprocessError, ParseError) as e:
            self._kill_clients()
            self._kill_nodes()
            raise BenchError("Failed to run benchmark", e)

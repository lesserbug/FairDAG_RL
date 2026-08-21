# Copyright(C) Facebook, Inc. and its affiliates.
from os.path import join, dirname

from benchmark.utils import PathMaker


class CommandMaker:

    @staticmethod
    def cleanup(username=None):
        if username:
            return f'rm -rf /var/scratch/{username}/narwhal/benchmark/.db-* ; rm /var/scratch/{username}/narwhal/benchmark/*.json ; mkdir -p {PathMaker.results_path()}'
        else:
            return f"rm .db-* ; rm .*.json ; mkdir -p {PathMaker.results_path()}"

    @staticmethod
    def clean_logs():
        return f'rm -r {PathMaker.logs_path()} ; mkdir -p {PathMaker.logs_path()}'

    @staticmethod
    def compile():
        return 'cargo build --quiet --release --features benchmark'
    
    @staticmethod
    def compile_hotstuff():
        return (
            'rm -f CMakeCache.txt '
            '&& rm -rf CMakeFiles cmake_install.cmake Makefile build '
            '&& cmake -DCMAKE_BUILD_TYPE=Release '
            '-DBUILD_SHARED=ON '
            '-DHOTSTUFF_PROTO_LOG=ON '
            '-DCMAKE_CXX_FLAGS="-include cstdint" && '
            'make -j'
        )

    @staticmethod
    def generate_key(filename):
        assert isinstance(filename, str)
        return f'./node generate_keys --filename {filename}'

    @staticmethod
    def run_primary(keys, committee, store, parameters, is_byzantine=0, debug=False):
        assert isinstance(keys, str)
        assert isinstance(committee, str)
        assert isinstance(parameters, str)
        assert isinstance(debug, bool)
        v = '-vvv' if debug else '-vv'
        return (f'./node {v} run --keys {keys} --committee {committee} '
                f'--store {store} --parameters {parameters} --is_byzantine {is_byzantine} primary')

    @staticmethod
    def run_worker(keys, committee, store, parameters, id, is_byzantine=0, debug=False):
        assert isinstance(keys, str)
        assert isinstance(committee, str)
        assert isinstance(parameters, str)
        assert isinstance(debug, bool)
        v = '-vvv' if debug else '-vv'
        return (f'./node {v} run --keys {keys} --committee {committee} '
                f'--store {store} --parameters {parameters} --is_byzantine {is_byzantine} worker --id {id}')

    @staticmethod
    def run_client(address, size, rate, nodes, client_id):
        assert isinstance(address, str)
        assert isinstance(size, int) and size > 0
        assert isinstance(rate, int) and rate >= 0
        assert isinstance(nodes, list)
        assert all(isinstance(x, str) for x in nodes)
        assert isinstance(client_id, int) and client_id >= 0
        nodes = f'--nodes {" ".join(nodes)}' if nodes else ''
        return (
            f'./benchmark_client {address} --size {size} --rate {rate} '
            f'--client-id {client_id} {nodes}'
        )
    
    # Themis
    @staticmethod
    def run_hotstuff_replicas(
        n_replicas,
        is_pompe_variant: bool = False
    ):

        assert isinstance(n_replicas, int) and n_replicas > 0

        cmds = []
        for i in range(n_replicas):
            if not is_pompe_variant:
                cmd = f"./examples/hotstuff-app --conf ./hotstuff-sec{i}.conf"
            else:
                benchmark_log_dir = join(dirname(dirname(__file__)), "logs")
                cmd = f"./examples/pompe-app ./conf-gen/hotstuff.conf {benchmark_log_dir}/server{i}.log --conf ./conf-gen/hotstuff-sec{i}.conf"
            cmds.append(cmd)
        return cmds

    # Themis
    @staticmethod
    def run_hotstuff_client(
        idx=0,
        max_async=400,
        tx_size=512,
        fairness=1.0,
        sb_users=1000000,
        sb_prob=0.9,
        sb_skew_factor=0.1,
        iter_count=-1,
        flavor: str = "hotstuff"
    ):
    
        if flavor not in [
            "hotstuff",
            "pompe"
        ]:
            cmd = (
                f"./examples/hotstuff-client "
                f"--idx {idx} "
                f"--iter {iter_count} "
                f"--max-async {max_async} "
                f"--max-cli-msg {tx_size} "
                f"--fairness-parameter {fairness} "
                f"--sb-users {sb_users} "
                f"--sb-prob-choose_mtx {sb_prob} "
                f"--sb-skew-factor {sb_skew_factor} "
            )
        elif flavor == "pompe":

            benchmark_log_dir = join(dirname(dirname(__file__)), "logs")

            cmd = (
                f"./examples/pompe-client "
                f"./conf-gen/hotstuff.conf {benchmark_log_dir}/client{idx}.order.log {benchmark_log_dir}/client{idx}.exec.log "
                f"--cid {idx} "
                f"--iter {iter_count} "
                f"--max-async {max_async} "
                f"--max-cli-msg {tx_size} "
            )
        else:
            cmd = (
                f"./examples/hotstuff-client "
                f"--idx {idx} "
                f"--iter {iter_count} "
                f"--max-async {max_async} "
                f"--max-cli-msg {tx_size} "
            )
        return cmd

    # Themis
    @staticmethod
    def generate_hotstuff_config(
        n_replica_ips: list,
        base_port=10000,
        block_size=100,
        fairness=1.0,
        sb_users=1000000,
        sb_prob=0.9,
        sb_skew_factor=0.1,
        flavor: str = "themis"
    ):
        
        assert isinstance(base_port, int)

        ips_path = join(PathMaker.hotstuff_code_path(flavor), "ips.txt")
        with open(ips_path, "w") as f:
            for replica_ip in n_replica_ips:
                f.write(f"{replica_ip}\n")

        # if flavor == "pompe":
        #     block_size = 1

        cmd = (
            f"python3 scripts/gen_conf.py " # There are other default params in 'gen_conf.py'
            f"--prefix hotstuff "
            f"--pport {base_port} "
            f"--cport {base_port + 10000} "
            f"--block-size {block_size} "
            f"--ips {ips_path} "
        )
        if flavor not in [
            "hotstuff",
            "pompe",
        ]:
            cmd += (
                f"--sb-users {sb_users} "
                f"--sb-prob-choose_mtx {sb_prob} "
                f"--sb-skew-factor {sb_skew_factor} "
                f"--fairness-parameter {fairness} "
            )

        return cmd

    @staticmethod
    def kill():
        return 'tmux kill-server'

    @staticmethod
    def kill_clients():
        return (
            "tmux list-sessions -F '#S' 2>/dev/null "
            "| grep '^client-' "
            "| xargs -r -n1 tmux kill-session -t"
        )

    @staticmethod
    def kill_nodes():
        return (
            "tmux list-sessions -F '#S' 2>/dev/null "
            "| grep -E '^(primary|worker)-' "
            "| xargs -r -n1 tmux kill-session -t"
        )

    @staticmethod
    def alias_binaries(origin):
        assert isinstance(origin, str)
        node, client = join(origin, 'node'), join(origin, 'benchmark_client')
        return f'rm node ; rm benchmark_client ; ln -s {node} . ; ln -s {client} .'

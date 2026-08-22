# Copyright(C) Facebook, Inc. and its affiliates.
from os.path import join, dirname, abspath
import traceback


CLIENT_RATE_PRECISION = 20


def distribute_client_rates(total_rate, active_clients):
    """Split an exact total rate into rates supported by the 20 Hz Rust client."""
    if active_clients <= 0:
        raise ValueError('There must be at least one active benchmark client')
    if total_rate <= 0 or total_rate % CLIENT_RATE_PRECISION != 0:
        raise ValueError(
            f'Input rate {total_rate} must be a positive multiple of '
            f'{CLIENT_RATE_PRECISION} tx/s'
        )

    total_bursts = total_rate // CLIENT_RATE_PRECISION
    base_bursts, remainder = divmod(total_bursts, active_clients)
    rates = [
        (base_bursts + (1 if i < remainder else 0))
        * CLIENT_RATE_PRECISION
        for i in range(active_clients)
    ]
    assert sum(rates) == total_rate
    return rates


def validate_crash_faults(faults, fault_threshold, nodes):
    """Reject crash-at-start configurations that cannot reach FairDAG quorum."""
    if faults > fault_threshold:
        raise ValueError(
            f'Crash faults={faults} exceed the configured FairDAG-RL '
            f'threshold {fault_threshold} for nodes={nodes}'
        )


class BenchError(Exception):
    def __init__(self, message, error=None):
        assert isinstance(error, Exception)
        self.message = message
        self.cause = error
        super().__init__(message)


class PathMaker:
    @staticmethod
    def binary_path():
        return join('..', 'target', 'release')

    @staticmethod
    def node_crate_path():
        return join('..', 'node')
    
    @staticmethod
    def hotstuff_code_path(flavor=None):
        benchmark_dir = dirname(dirname(__file__))
        root_dir = abspath(join(benchmark_dir, '..'))
        dir_name = 'libhotstuff'
        if(
            flavor == "themis"
        ):
            dir_name = 'Themis_tx'
        elif(
            flavor == "rashnu"
        ):
            dir_name = "Rashnu"
        elif(
            flavor == "dikaios"
        ):
            dir_name = "dikaios"
        elif(
            flavor == "pompe"
        ):
            dir_name = "Pompe-HS"
        return join(root_dir, 'of_protocols', dir_name)

    @staticmethod
    def hotstuff_log_file(name: str) -> str:
        return join(PathMaker.logs_path(), f'hotstuff-{name}.log')

    @staticmethod
    def committee_file():
        return '.committee.json'

    @staticmethod
    def parameters_file():
        return '.parameters.json'

    @staticmethod
    def key_file(i):
        assert isinstance(i, int) and i >= 0
        return f'.node-{i}.json'

    @staticmethod
    def db_path(i, j=None, username=None):
        assert isinstance(i, int) and i >= 0
        assert (isinstance(j, int) and i >= 0) or j is None
        worker_id = f'-{j}' if j is not None else ''
        if username:
            return f"/var/scratch/{username}/narwhal/benchmark/.db-{i}{worker_id}"
        else:
            return f".db-{i}{worker_id}"

    @staticmethod
    def logs_path():
        return 'logs'

    @staticmethod
    def primary_log_file(i):
        assert isinstance(i, int) and i >= 0
        return join(PathMaker.logs_path(), f'primary-{i}.log')

    @staticmethod
    def worker_log_file(i, j):
        assert isinstance(i, int) and i >= 0
        assert isinstance(j, int) and i >= 0
        return join(PathMaker.logs_path(), f'worker-{i}-{j}.log')

    @staticmethod
    def client_log_file(i, j):
        assert isinstance(i, int) and i >= 0
        # assert isinstance(j, int) and i >= 0
        return join(PathMaker.logs_path(), f'client-{i}-{j}.log')

    @staticmethod
    def results_path():
        return 'results'
    
    @staticmethod
    def local_result_file(
        attack_type, arbitragers, faults, workers, nodes
    ):
        return join(
            PathMaker.results_path(),
            f"local-{attack_type}-{arbitragers}-{faults}-{workers}-{nodes}.txt",
        )

    @staticmethod
    def result_file(
        attack_type, arbitragers, faults, workers, nodes, batch_size=None
    ):
        batch_suffix = '' if batch_size is None else f'-b{batch_size}'
        return join(
            PathMaker.results_path(),
            f"remote-{attack_type}-{arbitragers}-{faults}-{workers}-{nodes}"
            f"{batch_suffix}.txt",
        )

    @staticmethod
    def plots_path():
        return 'plots'

    @staticmethod
    def agg_file(type, faults, nodes, workers, collocate, rate, tx_size, max_latency=None):
        if max_latency is None:
            name = f'{type}-bench-{faults}-{nodes}-{workers}-{collocate}-{rate}-{tx_size}.txt'
        else:
            name = f'{type}-{max_latency}-bench-{faults}-{nodes}-{workers}-{collocate}-{rate}-{tx_size}.txt'
        return join(PathMaker.plots_path(), name)

    @staticmethod
    def plot_file(name, ext):
        return join(PathMaker.plots_path(), f'{name}.{ext}')


class Color:
    HEADER = '\033[95m'
    OK_BLUE = '\033[94m'
    OK_GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Print:
    @staticmethod
    def heading(message):
        assert isinstance(message, str)
        print(f'{Color.OK_GREEN}{message}{Color.END}')

    @staticmethod
    def info(message):
        assert isinstance(message, str)
        print(message)

    @staticmethod
    def warn(message):
        assert isinstance(message, str)
        print(f'{Color.BOLD}{Color.WARNING}WARN{Color.END}: {message}')

    @staticmethod
    def error(e):
        assert isinstance(e, BenchError)
        print(f'\n{Color.BOLD}{Color.FAIL}ERROR{Color.END}: {e}\n')
        causes, current_cause = [], e.cause
        while isinstance(current_cause, BenchError):
            causes += [f'  {len(causes)}: {e.cause}\n']
            current_cause = current_cause.cause
        causes += [f'  {len(causes)}: {type(current_cause)}\n']
        causes += [f'  {len(causes)}: {current_cause}\n']
        print(f'Caused by: \n{"".join(causes)}\n')
        print('-----------------')
        print(f"TRACEBACK\n-----------------\n {traceback.format_exc()}")
        print('-----------------')


def progress_bar(iterable, prefix='', suffix='', decimals=1, length=30, fill='█', print_end='\r'):
    total = len(iterable)

    def printProgressBar(iteration):
        formatter = '{0:.'+str(decimals)+'f}'
        percent = formatter.format(100 * (iteration / float(total)))
        filledLength = int(length * iteration // total)
        bar = fill * filledLength + '-' * (length - filledLength)
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=print_end)

    printProgressBar(0)
    for i, item in enumerate(iterable):
        yield item
        printProgressBar(i + 1)
    print()

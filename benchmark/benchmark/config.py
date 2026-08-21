# Copyright(C) Facebook, Inc. and its affiliates.
from json import dump, load
from collections import OrderedDict
from random import sample
import socket

class ConfigError(Exception):
    pass


class Key:
    def __init__(self, name, secret):
        self.name = name
        self.secret = secret

    @classmethod
    def from_file(cls, filename):
        assert isinstance(filename, str)
        with open(filename, 'r') as f:
            data = load(f)
        return cls(data['name'], data['secret'])


class Committee:
    ''' The committee looks as follows:
        "authorities: {
            "name": {
                "stake": 1,
                "primary: {
                    "primary_to_primary": x.x.x.x:x,
                    "worker_to_primary": x.x.x.x:x,
                },
                "workers": {
                    "0": {
                        "primary_to_worker": x.x.x.x:x,
                        "worker_to_worker": x.x.x.x:x,
                        "transactions": x.x.x.x:x
                    },
                    ...
                }
            },
            ...
        }
    '''

    def __init__(self, addresses, base_port, attack_types=None):
        ''' The `addresses` field looks as follows:
            { 
                "name": ["host", "host", ...],
                ...
            }
        '''
        assert isinstance(addresses, OrderedDict)
        assert all(isinstance(x, str) for x in addresses.keys())
        assert all(
            isinstance(x, list) and len(x) > 1 for x in addresses.values()
        )
        assert all(
            isinstance(x, str) for y in addresses.values() for x in y
        )
        assert len({len(x) for x in addresses.values()}) == 1
        assert isinstance(base_port, int) and base_port > 1024

        port = base_port
        self.json = {'authorities': OrderedDict()}

        if attack_types is None:
            # Rust's Authority schema requires this field. Remote honest-only
            # benchmarks do not otherwise need an attack layout.
            attack_types = [0] * len(addresses)
        assert len(attack_types) == len(addresses)

        counter = 0
        for name, hosts in addresses.items():
            host = hosts.pop(0)
            primary_addr = {
                'primary_to_primary': f'{host}:{port}',
                'worker_to_primary': f'{host}:{port + 1}'
            }
            port += 2

            workers_addr = OrderedDict()
            for j, host in enumerate(hosts):
                workers_addr[j] = {
                    'primary_to_worker': f'{host}:{port}',
                    'transactions': f'{host}:{port + 1}',
                    'worker_to_worker': f'{host}:{port + 2}',
                }
                port += 3

            self.json['authorities'][name] = {
                'stake': 1,
                'primary': primary_addr,
                'workers': workers_addr
            }

            self.json['authorities'][name]["attack_type"] = attack_types[counter]

            counter += 1

    def primary_addresses(self, faults=0):
        ''' Returns an ordered list of primaries' addresses. '''
        assert faults < self.size()
        addresses = []
        good_nodes = self.size() - faults
        for authority in list(self.json['authorities'].values())[:good_nodes]:
            addresses += [authority['primary']['primary_to_primary']]
        return addresses
    
    def attacker_primary_addresses(self, attack_type, faults=0):
        """Returns an ordered list of primaries' addresses."""
        assert faults < self.size()
        addresses = []
        good_nodes = self.size() - faults
        for authority in list(self.json["authorities"].values())[:good_nodes]:
            if authority["attack_type"] == attack_type:
                addresses += [authority["primary"]["primary_to_primary"]]
        return addresses

    def workers_addresses(self, faults=0):
        ''' Returns an ordered list of list of workers' addresses. '''
        assert faults < self.size()
        addresses = []
        good_nodes = self.size() - faults
        for authority in list(self.json['authorities'].values())[:good_nodes]:
            authority_addresses = []
            for id, worker in authority['workers'].items():
                authority_addresses += [(id, worker['transactions'])]
            addresses.append(authority_addresses)
        return addresses
    
    def attacker_workers_addresses(self, attack_type, faults=0):
        """Returns an ordered list of list of workers' addresses."""
        assert faults < self.size()
        addresses = []
        good_nodes = self.size() - faults
        for authority in list(self.json["authorities"].values())[:good_nodes]:
            # 1: fissure; 3: sluggish; 5: pick-max; 10: monitoring
            if authority["attack_type"] == attack_type:
                authority_addresses = []
                for id, worker in authority["workers"].items():
                    authority_addresses += [(id, worker["transactions"])]
                addresses.append(authority_addresses)
        return addresses

    def get_byzantine_nodes(self, f):
        
        assert isinstance(f, int) and f >= 0
        assert f <= self.size(), "Cannot select more Byzantine nodes than total nodes"
        
        # if self.attack_type in {0, 10}:
        #     target_attack_types = {0}
        # else:
        #     target_attack_types = {2, 4, 6}
        
        # candidate_indices = []
        # for idx, (_, authority) in enumerate(self.json['authorities'].items()):
        #     if 'attack_type' in authority and authority['attack_type'] in target_attack_types:
        #         candidate_indices.append(idx)
        
        # if not candidate_indices:
        
        candidate_indices = list(range(self.size()))
        
        assert len(candidate_indices) >= f, \
            f"Not enough candidate nodes ({len(candidate_indices)}) for {f} Byzantine nodes"
        
        return sample(candidate_indices, f)

    def ips(self, name=None):
        ''' Returns all the ips associated with an authority (in any order). '''
        if name is None:
            names = list(self.json['authorities'].keys())
        else:
            names = [name]

        ips = set()
        for name in names:
            addresses = self.json['authorities'][name]['primary']
            ips.add(self.ip(addresses['primary_to_primary']))
            ips.add(self.ip(addresses['worker_to_primary']))

            for worker in self.json['authorities'][name]['workers'].values():
                ips.add(self.ip(worker['primary_to_worker']))
                ips.add(self.ip(worker['worker_to_worker']))
                ips.add(self.ip(worker['transactions']))

        return list(ips)

    def remove_nodes(self, nodes):
        ''' remove the `nodes` last nodes from the committee. '''
        assert nodes < self.size()
        for _ in range(nodes):
            self.json['authorities'].popitem()

    def size(self):
        ''' Returns the number of authorities. '''
        return len(self.json['authorities'])

    def workers(self):
        ''' Returns the total number of workers (all authorities altogether). '''
        return sum(len(x['workers']) for x in self.json['authorities'].values())

    def print(self, filename):
        assert isinstance(filename, str)
        with open(filename, 'w') as f:
            dump(self.json, f, indent=4, sort_keys=True)

    @staticmethod
    def ip(address):
        assert isinstance(address, str)
        return address.split(':')[0]


class LocalCommittee(Committee):
    def __init__(self, names, port, workers, faults, arbitragers, attack_type):
        assert isinstance(names, list)
        assert all(isinstance(x, str) for x in names)
        assert isinstance(port, int)
        assert isinstance(workers, int) and workers > 0
        assert isinstance(faults, int) and faults >= 0
        assert isinstance(arbitragers, int) and arbitragers >= 0
        node_num = len(names)
        assert faults + arbitragers < node_num
        attack_types = []
        if attack_type == 0:
            attack_types = [0] * node_num
        elif attack_type == 1: # fissure attack
            attack_types = [0] * (node_num - faults - arbitragers) + [1] + [2] * (
                faults + arbitragers - 1
            )
        elif attack_type == 2: # sluggish attack
            attack_types = [0] * (node_num - faults - arbitragers) + [3] + [4] * (
                faults + arbitragers - 1
            )
        elif attack_type == 3: # minimun digest attack
            attack_types = [0] * (node_num - faults - arbitragers) + [5] + [6] * (
                faults + arbitragers - 1
            )
        elif attack_type == 10: # just monitor
            attack_types = [0] * (node_num - faults - arbitragers) + [10] + [0] * (
                faults + arbitragers - 1
            )

        addresses = OrderedDict((x, ['127.0.0.1'] * (1 + workers)) for x in names)
        super().__init__(addresses, port, attack_types)

class DASCommittee(Committee):
    def __init__(self, names, port, workers, faults, arbitragers, attack_type, hostnames):
        assert isinstance(names, list)
        assert all(isinstance(x, str) for x in names)
        assert isinstance(port, int)
        assert isinstance(workers, int) and workers > 0
        assert isinstance(faults, int) and faults >= 0
        # assert isinstance(attack_type, int) and attack_type <= 3
        node_num = len(names)
        collocate = len(hostnames) == node_num

        assert faults + arbitragers < node_num
        attack_types = []
        if attack_type == 0:
            attack_types = [0] * node_num
        elif attack_type == 1:  # fissure attack
            # 1 builds the fissure, N-f-a victims, remaining f+a-1 are "passive" attackers (identical to active, but not logging)
            attack_types = (
                [0] * (node_num - faults - arbitragers)
                + [1]
                + [2] * (faults + arbitragers - 1)
            )
        elif attack_type == 2:  # sluggish attack
            # 1 builds the sluggish, N-f-a victims, remaining f+a-1 are "passive" attackers (identical to active, but not logging)
            attack_types = (
                [0] * (node_num - faults - arbitragers)
                + [3]
                + [4] * (faults + arbitragers - 1)
            )
        elif attack_type == 3:  # minimun digest attack
            # 1 tries multiple blocks, N-f-a victims, remaining f+a-1 are "passive" attackers (identical to active, but not logging)
            attack_types = (
                [0] * (node_num - faults - arbitragers)
                + [5]
                + [6] * (faults + arbitragers - 1)
            )
        elif attack_type == 10:  # just monitor
            attack_types = (
                [0] * (node_num - faults - arbitragers)
                + [10]
                + [0] * (faults + arbitragers - 1)
            )

        node_amount = workers + 1
        if collocate:
            addresses = OrderedDict((x, [socket.gethostbyname(hostnames[i])] * node_amount) for i, x in enumerate(names))
        else:
            addresses = OrderedDict((x, list(map(socket.gethostbyname, hostnames[i*node_amount:(i+1)*node_amount]))) for i, x in enumerate(names))

        super().__init__(addresses, port, attack_types)

class NodeParameters:
    def __init__(self, json):
        inputs = []
        try:
            inputs += [json['header_size']]
            inputs += [json['max_header_delay']]
            inputs += [json['gc_depth']]
            inputs += [json['sync_retry_delay']]
            inputs += [json['sync_retry_nodes']]
            inputs += [json['batch_size']]
            inputs += [json['max_batch_delay']]
            inputs += [json['fault_threshold']]
        except KeyError as e:
            raise ConfigError(f'Malformed parameters: missing key {e}')

        if not all(isinstance(x, int) for x in inputs):
            raise ConfigError('Invalid parameters type')
        
        if not isinstance(json['gamma'], float):
            raise ConfigError('Invalid parameters type: gamma')
        
        if not isinstance(json['scc_ordering'], str):
            raise ConfigError('Invalid parameters type: scc_ordering')

        self.json = json

    def print(self, filename):
        assert isinstance(filename, str)
        with open(filename, 'w') as f:
            dump(self.json, f, indent=4, sort_keys=True)


class BenchParameters:
    def __init__(self, json):
        try:
            self.faults = int(json['faults'])

            self.arbitragers = int(json["arbitragers"])
            self.attack_type = int(json["attack_type"])

            nodes = json['nodes']
            nodes = nodes if isinstance(nodes, list) else [nodes]
            if not nodes or any(x <= 1 for x in nodes):
                raise ConfigError('Missing or invalid number of nodes')
            self.nodes = [int(x) for x in nodes]

            rate = json['rate']
            rate = rate if isinstance(rate, list) else [rate]
            if not rate:
                raise ConfigError('Missing input rate')
            self.rate = [int(x) for x in rate]

            
            self.workers = int(json['workers'])

            if 'collocate' in json:
                self.collocate = bool(json['collocate'])
            else:
                self.collocate = True

            self.tx_size = int(json['tx_size'])
           
            self.duration = int(json['duration'])
            self.drain_duration = int(json.get('drain_duration', 0))

            self.runs = int(json['runs']) if 'runs' in json else 1
        except KeyError as e:
            raise ConfigError(f'Malformed bench parameters: missing key {e}')

        except ValueError:
            raise ConfigError('Invalid parameters type')

        if min(self.nodes) <= self.faults:
            raise ConfigError('There should be more nodes than faults')

        if self.drain_duration < 0:
            raise ConfigError('Drain duration must be non-negative')


class PlotParameters:
    def __init__(self, json):
        try:
            faults = json['faults']
            faults = faults if isinstance(faults, list) else [faults]
            self.faults = [int(x) for x in faults] if faults else [0]

            nodes = json['nodes']
            nodes = nodes if isinstance(nodes, list) else [nodes]
            if not nodes:
                raise ConfigError('Missing number of nodes')
            self.nodes = [int(x) for x in nodes]

            workers = json['workers']
            workers = workers if isinstance(workers, list) else [workers]
            if not workers:
                raise ConfigError('Missing number of workers')
            self.workers = [int(x) for x in workers]

            if 'collocate' in json:
                self.collocate = bool(json['collocate'])
            else:
                self.collocate = True

            self.tx_size = int(json['tx_size'])

            max_lat = json['max_latency']
            max_lat = max_lat if isinstance(max_lat, list) else [max_lat]
            if not max_lat:
                raise ConfigError('Missing max latency')
            self.max_latency = [int(x) for x in max_lat]

        except KeyError as e:
            raise ConfigError(f'Malformed bench parameters: missing key {e}')

        except ValueError:
            raise ConfigError('Invalid parameters type')

        if len(self.nodes) > 1 and len(self.workers) > 1:
            raise ConfigError(
                'Either the "nodes" or the "workers can be a list (not both)'
            )

    def scalability(self):
        return len(self.workers) > 1

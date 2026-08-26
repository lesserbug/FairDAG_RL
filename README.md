# FairDAG-RL

This repository contains the FairDAG-RL baseline used in our experiments.

The code is derived from the public Narwhal/Tusk-based FairDAG-RL implementation in the
[Herring artifact](https://github.com/randomUserGithub123/narwhal/tree/fairdag).
FairDAG-RL uses replica transaction-order observations to construct a fair ordering graph
on top of the committed DAG.

The `codex/mrv-benchmark-align` branch contains the version used for our benchmarking,
including support for controlled local/AWS experiments, crash and batch-size sensitivity
experiments, and final-order throughput/latency measurements.

This repository is intended for research and benchmarking only. It is not production software.

## Setup

Clone the benchmark branch:

```bash
git clone \
  --branch codex/mrv-benchmark-align \
  --single-branch \
  https://github.com/lesserbug/FairDAG_RL.git \
  FairDAG_RL

cd FairDAG_RL/benchmark
pip install -r requirements.txt

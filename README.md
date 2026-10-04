# auth-mpc-impementation

Proof-of-concept implementation of authenticated MPC: the distributed proof of
knowledge of a BBS signature on secret-shared inputs from Section 4 of
[ePrint 2022/1648](2022-1648.pdf).

Each of N = 5 provers holds a Shamir share (threshold 2) of every party's
message vector. Together they prove that the shared messages carry valid BBS
signatures. The provers talk through a zeromq broadcast hub. The input shares
come from [MP-SPDZ](https://github.com/data61/MP-SPDZ).

## Components

For how the code works (protocol-to-code mapping, message flow, data formats, known
limitations), see the [code guide](docs/CODE.md).

| File | Purpose |
|------|---------|
| `dpok-bbs.cpp`, `dpok-bbs.hpp` | Section 4 protocol: randomised BBS statement, then the DPOK on D plus the DPOKs for C and A. Runs 5 provers as threads. |
| `dpok-dlog.cpp`, `dpok-dlog.hpp` | Distributed PoK of an opening of a vector commitment (sub-protocol). `dpok-dlog` is a standalone test. |
| `nipk.hpp` | Non-interactive (log-size) proof of knowledge used inside the DPOKs |
| `bbs.hpp` | BBS key generation, signing, verification over alt_bn128 (libff) |
| `broadcasthub.hpp`, `broadcastclient.hpp`, `hub_server.cpp` | zeromq ROUTER/DEALER broadcast hub: collects one message per prover per round and broadcasts the bundle |
| `mpspdz/bbs_share.mpc` | MP-SPDZ program that Shamir-shares every party's message and writes the shares to `Persistence/` |
| `mpspdz/gen_inputs.py` | Generates random message vectors for each party |
| `run.sh` | End-to-end pipeline (build, inputs, sharing, hub, provers) |
| `runbbsprover.cpp`, `bbsauthprover.*`, `pokprover.*`, `setup.cpp` | Older 3-party prototype (not built by default, not maintained) |

## Installation

Tested on Ubuntu 24.04 with g++ 13.3 and cmake 3.28.

### 1. System packages

```bash
sudo apt install -y build-essential cmake libgmp-dev libssl-dev libzmq3-dev nlohmann-json3-dev python3
```

### 2. libff (alt_bn128)

By default, `CMakeLists.txt` looks for libff in `../deps/libff-install`:

```bash
mkdir -p ../deps && cd ../deps
git clone --depth 1 https://github.com/scipr-lab/libff.git
cd libff
cmake -S . -B build -DCURVE=ALT_BN128 -DWITH_PROCPS=OFF -DIS_LIBFF_PARENT=OFF \
      -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$PWD/../libff-install
cmake --build build -j --target ff
cmake --install build
```

To use a libff installed somewhere else, pass `-DLIBFF_PREFIX=/path/to/prefix` to cmake.

### 3. MP-SPDZ

Download a release (tested with 0.4.3) next to this repository, so that it
sits at `../mp-spdz-0.4.3`:

```bash
cd ..
wget https://github.com/data61/MP-SPDZ/releases/download/v0.4.3/mp-spdz-0.4.3.tar.xz
tar xf mp-spdz-0.4.3.tar.xz
```

Only `compile.py`, `Scripts/shamir.sh` and `shamir-party.x` are used.
`run.sh` creates the SSL certificates for the parties on its first run.

### 4. Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## Running

```bash
./run.sh [rows] [cols]                   # message size n = rows*cols (default 400*10 = 4000)
MPSPDZ=/path/to/mp-spdz ./run.sh 100 10  # n = 1000, with MP-SPDZ in a non-default location
```

`run.sh` performs these steps:

1. Writes `rows x cols` random integers per party to `$MPSPDZ/Player-Data/Input-P<i>-0`.
2. Compiles and runs `bbs_share.mpc` with `shamir-party.x` (5 parties, threshold 2), over the
   BN254 scalar field
   `p = 21888242871839275222246405745257275088548364400416034343698204186575808495617`.
   The shares end up in `$MPSPDZ/Persistence/Transactions-P<i>.data`.
3. Starts `hub_server 5` on `127.0.0.1:8000`.
4. Runs `dpok-bbs $MPSPDZ n`. This generates BBS keys, signs each party's message and
   reads the shares. It then runs the 5 provers.

Each prover prints `[ status , bytes sent , bytes received ]`. A status of `1`
means every DPOK verified, including the reconstruction checks with the
Lagrange coefficients (5, -10, 10, -5, 1).

Sample output (n = 4000):

```
Prover 3: [ 1 , 3153 , 16161 ]
Prover 2: [ 1 , 3153 , 16161 ]
...
All threads exited: 2650 ms
```

### Running the steps manually

```bash
# MP-SPDZ sharing (from the MP-SPDZ directory)
./compile.py -F 254 bbs_share 5 <n>
Scripts/setup-ssl.sh 5
rm -f Persistence/Transactions-P*.data          # write_to_file appends
Scripts/shamir.sh -N 5 -P <p> bbs_share-5-<n>

# provers (from build/)
./hub_server 5 &
./dpok-bbs <mpspdz_dir> <n>
```

### Notes and troubleshooting

- **MP-SPDZ compile flags:** compile with `-F 254` and pass the prime only at runtime (`-P`).
  In MP-SPDZ 0.4.3, `compile.py -P <prime>` crashes when the Python package `gmpy2` is not installed.
- **Share file format:** MP-SPDZ stores shares in Montgomery form (R = 2^256), and since
  version 0.3 it puts a header at the start of each Persistence file.
  `read_elements_montgomery` in `utility.hpp` skips the header and converts the shares to
  regular field elements.
- **Port 8000 in use:** a `hub_server` from an interrupted run may still be holding the port.
  Run `pkill -x hub_server`.
- **Number of provers:** N = 5 is fixed at compile time (`test_dpok_bbs_mp_spdz<ppT, 5>`)
  and must match `NPARTIES` in `run.sh` and the reconstruction coefficients.
- **Byte counts:** libff is built with its default binary point serialization, which
  determines the reported byte counts.

## Benchmark

Setup: 5 provers on one machine (Intel Core i9-14900HX, 32 threads, 94 GB RAM), with the hub
on loopback. `./run.sh <n/10> 10`, 3 runs per size; all runs verified (status 1).

- **Time:** wall-clock time of the interactive phase for all 5 provers together (the
  `All threads exited` line). It does not include key generation, signing or the MP-SPDZ sharing.
- **Communication:** per prover, reported by prover 0.

| Message size n | Time (median of 3) | Runs (ms) | Bytes sent / prover | Bytes received / prover |
|---------------:|-------------------:|----------:|--------------------:|------------------------:|
| 500  | 246 ms  | 246, 248, 245    | ~2.95 KB | ~15.1 KB |
| 1000 | 467 ms  | 466, 467, 483    | ~3.02 KB | ~15.5 KB |
| 1500 | 846 ms  | 864, 829, 846    | ~3.09 KB | ~15.8 KB |
| 2000 | 1037 ms | 1037, 1052, 1020 | ~3.09 KB | ~15.8 KB |

- Time grows roughly linearly in n.
- Communication grows logarithmically in n. The witness is padded to the next power of two,
  so 1500 and 2000 both use 2048 and send the same amount.
- Each prover receives about 5x what it sends, because the hub broadcasts every prover's
  message to all of them.

To reproduce:

```bash
for r in 50 100 150 200; do ./run.sh $r 10; done
```

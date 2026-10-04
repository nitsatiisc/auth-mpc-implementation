#!/usr/bin/env bash
# End-to-end run of the distributed BBS proof (dpok-bbs) with 5 provers.
#
#   1. generate random message vectors  -> $MPSPDZ/Player-Data/Input-P<i>-0
#   2. Shamir-share them with MP-SPDZ    -> $MPSPDZ/Persistence/Transactions-P<i>.data
#   3. start the zmq broadcast hub (127.0.0.1:8000)
#   4. run dpok-bbs (5 prover threads; each prints [status, bytes sent, bytes recv])
#
# Usage: ./run.sh [rows] [cols]      (message size n = rows*cols, default 400*10)
# Env:   MPSPDZ=/path/to/mp-spdz     (default ../mp-spdz-0.4.3)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
MPSPDZ="$(cd "${MPSPDZ:-$ROOT/../mp-spdz-0.4.3}" && pwd)"
ROWS="${1:-400}"
COLS="${2:-10}"
N_MSG=$((ROWS * COLS))
NPARTIES=5     # must match test_dpok_bbs_mp_spdz<ppT, 5> in dpok-bbs.cpp
# BN254 (alt_bn128) scalar field order = libff Fr<alt_bn128_pp>
PRIME=21888242871839275222246405745257275088548364400416034343698204186575808495617

echo "== building"
cmake -S "$ROOT" -B "$ROOT/build" -DCMAKE_BUILD_TYPE=Release > /dev/null
cmake --build "$ROOT/build" -j"$(nproc)" --target dpok-bbs hub_server > /dev/null

echo "== generating inputs ($NPARTIES parties, n=$N_MSG)"
python3 "$ROOT/mpspdz/gen_inputs.py" "$MPSPDZ/Player-Data" "$NPARTIES" "$ROWS" "$COLS"

echo "== secret sharing with MP-SPDZ (shamir, $NPARTIES parties)"
cp "$ROOT/mpspdz/bbs_share.mpc" "$MPSPDZ/Programs/Source/"
(
    cd "$MPSPDZ"
    # -F instead of -P: 0.4.3's compiler crashes on -P without gmpy2
    ./compile.py -F 254 bbs_share "$NPARTIES" "$N_MSG" > /dev/null
    [ -f "Player-Data/P$((NPARTIES - 1)).pem" ] || Scripts/setup-ssl.sh "$NPARTIES" > /dev/null
    mkdir -p Persistence
    rm -f Persistence/Transactions-P*.data   # write_to_file appends
    Scripts/shamir.sh -N "$NPARTIES" -P "$PRIME" "bbs_share-$NPARTIES-$N_MSG" > /dev/null 2>&1
)

echo "== running distributed BBS prover"
cd "$ROOT/build"
if ss -ltn | grep -q ':8000 '; then
    echo "port 8000 already in use (stale hub_server? try: pkill -x hub_server)" >&2
    exit 1
fi
./hub_server "$NPARTIES" &
HUB=$!
trap 'kill $HUB 2>/dev/null || true' EXIT
sleep 0.5
./dpok-bbs "$MPSPDZ" "$N_MSG" 2>&1 | grep -E "Prover|All threads"

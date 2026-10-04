# Code Guide

This guide explains how the C++ code is organised and how the distributed BBS proof
(`dpok-bbs`) works. See the [README](../README.md) for installation and running.

All code is header-only templates on top of [libff](https://github.com/scipr-lab/libff).
Throughout:

- `ppT = alt_bn128_pp`: the BN254 pairing curve.
- `GroupT = G1<ppT>`: the group used for every commitment and proof.
- `FieldT = Fr<ppT>`: the scalar field. MP-SPDZ shares over the same prime.
- `N`: the number of provers (a template parameter, 5 in `dpok-bbs.cpp`).
- `n`: the length of each party's BBS message vector.

## 1. Big picture

```
           MP-SPDZ (shamir, 5 parties)                         dpok-bbs (one process, 5 threads)
 Input-P<i>-0 ──► bbs_share.mpc ──► Persistence/Transactions-P<j>.data ──┐
 (party i's message m_i)            (party j's shares of m_0..m_4)       │
                                                                         ▼
                                     test_dpok_bbs_mp_spdz: keygen, sign m_i, deal shares of
                                     (e, r, v, t, eta), read message shares, start provers
                                                                         │
                     ┌──────────────┬──────────────┬─────────────────────┤
                  Prover 0      Prover 1        ...                  Prover 4   (ProtocolBBS)
                     │              │                                    │
                     └──────────────┴──── BroadcastClient (zmq DEALER) ──┘
                                              │
                                   hub_server (zmq ROUTER, 127.0.0.1:8000)
                                   waits for one message from every prover,
                                   then broadcasts the bundle to all of them
```

Every prover runs the same code. It publishes one message per round to the hub and
then receives the bundle of all provers' messages for that round. Every prover then
derives the same Fiat–Shamir challenges from that common transcript.

## 2. Protocol to code mapping

### 2.1 BBS signatures (`bbs.hpp`)

| Item | Code |
|------|------|
| Public params: `g1, h_0..h_n ∈ G1`, `g2 ∈ G2` | `BBSPublicParams` (`h` holds `h_0..h_n`) |
| Key pair: `sk = x`, `vk = x·g2` | `BBSKeyPair` |
| Signature `(A, e, s)` with `A = (x+e)^{-1} · (g1 + s·h_0 + Σ m_k·h_k)` | `BBSSignature`, `sign` / `sign_message` |
| Pairing check `e(A, vk + e·g2) = e(b, g2)` | `verify` |
| File I/O | `generateParams` and `readFullParams` write/read `<name>_pp.dat`, `_sk.dat`, `_vk.dat`; `readMessage` |

### 2.2 Randomised statement (`ProtocolBBS::compute_randomized_statement`)

Each prover i holds its own signature `(A, e, s)` on `m_i`, plus random `u, r, eta`. It computes:

```
b     = g1 + s·h_0 + Σ m_k·h_k
v     = u^{-1},   t = s − r·v
d     = u·b − r·h_0
A'    = u·A                      (a_dash)
Ā     = u·b − e·A'               (a_bar)
C     = (t − eta)·h_0 − v·d      ( = −g1 − eta·h_0 − Σ m_k·h_k )
D     = −(C + g1)                ( =  eta·h_0 + Σ m_k·h_k )
```

These five points are prover i's round-1 message. Proving knowledge of openings of C,
D and `Ā − d` (below), together with the pairing check on `(A', Ā)`, proves possession
of a valid signature on the committed message.

### 2.3 Distributed proofs of knowledge (`ProtocolBBS::run_interactive_phase_private`)

The secret values are Shamir-shared among the provers, so each proof is a
**distributed** PoK (`ProtocolDlog`). Every prover works on its own shares, and the
shares are combined "in the exponent" with the Lagrange coefficients
`reconstruct_coefficients = (5, −10, 10, −5, 1)`.

| Proof | Statement (public) | Generators | Witness (each prover uses its shares) | Runs |
|-------|--------------------|------------|----------------------------------------|------|
| D (big) | `D = Σ_j γ^j · D_j` | `h_0..h_n` | `y = (Σ_j γ^j·[eta_j], Σ_j γ^j·[m_j])`, length n+1 | once, batched over all N parties with challenge γ |
| C | `C_i` | `(d_i, h_0)` | `(−[v_i], [t_i] − [eta_i])` | once per party i |
| A | `Ā_i − d_i` | `(A'_i, h_0)` | `(−[e_i], [r_i])` | once per party i |

`[x]` denotes this prover's Shamir share of x. γ is a Fiat–Shamir challenge computed
from the bundle of all round-1 messages.

### 2.4 One distributed PoK round trip (`ProtocolDlog` in `dpok-dlog.hpp`)

Each `ProtocolDlog::run_interactive_phase` takes **two hub rounds**:

1. **Commit.** Prover j publishes `A_j = <gens, ss_j>`, a commitment to its share vector.
   In robust mode it also publishes `B_j = <h, (rr_j, ρ)>`.
2. **Challenge.** The prover derives a challenge vector from the round-1 bundle and computes
   `v_j = <challenge, ss_j> (+ rr_j)`.
3. **Prove.** The prover publishes `proofA`, a NIPK that it knows an opening of `A_j`. In robust
   mode it also publishes `proofB`, and `proofC`, which shows that `A_j + B_j` opens to a vector
   whose linear form evaluates to `v_j`.
4. **Verify.** Every prover verifies all N proofs and checks the reconstruction equation
   `Σ_j λ_j · A_j == commitment`.

`dpok-bbs` calls these with `robust = false`. In that mode only `A_j`, `proofA` and the
reconstruction check run.

### 2.5 Non-interactive PoK (`nipk.hpp`)

`NonInteractiveProof` proves knowledge of `s` such that `<g, s> = P` and `<L, s> = y`.
It is a Bulletproofs-style folding argument (a compressed Σ-protocol):

- The linear form is folded into the commitment through an extra generator `k_gen`
  (`P + c·y·k_gen`).
- Each round halves the vectors and emits two group elements `(a, b)`.
- The proof is `2·log2(n)` group elements plus one field element.
- Vectors are zero-padded to the next power of two. This is why proof size and
  communication only change at powers of two.

`NonInteractiveProofVerifier::verify` recomputes the challenges, expands the folded
generator in closed form (`re_comb_G`), and checks a single multi-exponentiation equation.
`Statement` = `(gens, k_gen, commitment, linear_form, value)`.

### 2.6 Message flow of one `dpok-bbs` run

```
round 1        : randomised statements (a_dash, a_bar, d, C, D) from every prover
rounds 2..2N+1 : N × ProtocolDlog for C_i      (2 rounds each)
next 2N rounds : N × ProtocolDlog for Ā_i − d_i (2 rounds each)
last 2 rounds  : ProtocolDlog for the batched D
```

With N = 5 that is 23 hub rounds. Each prover finally prints
`Prover i: [ status , bytes sent , bytes received ]`.

## 3. File reference

### Protocol

| File | Contents |
|------|----------|
| `dpok-bbs.hpp` | `ProtocolBBSPublicParams` (BBS params, two extra generators `h` for robust mode, `k_gen` for the NIPK, Lagrange coefficients), `ProtocolBBSProverInput` (own signature/message/randomness + this prover's shares of everyone's `e, r, v, t, eta, m`), `RandomizedStatement`, `ProtocolBBS<ppT, N>` |
| `dpok-bbs.cpp` | Test driver. `test_dpok_bbs_mp_spdz<ppT, N>(mpspdz_dir, n)` is used by `main`: it reads messages from `Player-Data`, signs them, deals shares of the scalars with `ShamirShare<FieldT, 1, N>`, reads the message shares from `Persistence`, and runs N `std::thread`s. `test_dpok_bbs_proto` is an older variant that deals all shares locally (no MP-SPDZ). |
| `dpok-dlog.hpp` | `ProtocolDlogPublicParams`, `ProtocolDlogWorkerInput` (`ss` = share vector, `commitment`, `rr` = share of masking randomness), `ProtocolDlog<GroupT, FieldT, N>` |
| `dpok-dlog.cpp` | Standalone test: one random commitment of size 32, shared with `ShamirShareVec<FieldT, 2, 5>`, proven by 5 threads |
| `nipk.hpp` | `Statement`, `NonInteractiveProof`, `NonInteractiveProofVerifier`, tests `test_nipk_proof` and `test_nipk_multiple_proofs_parsing` |
| `bbs.hpp` | BBS signature scheme (see §2.1) |

### Infrastructure

| File | Contents |
|------|----------|
| `broadcastclient.hpp` | `BroadcastClient`: zmq DEALER. `register_with_hub()`, `send_message_to_hub()`, `recv_message_from_hub()`, byte counters. Also the protocol codes and socket helpers. |
| `broadcasthub.hpp` | `BroadcastHub`: zmq ROUTER. Collects one message per client per round and broadcasts the bundle. |
| `hub_server.cpp` | `hub_server <nclients>`: runs a `BroadcastHub` on `127.0.0.1:8000` |
| `bulletinboard.hpp` | `BulletinBoard<ChannelT>`: thin wrapper with `publish()` / `get_all_messages()`. `ChannelT` is `BroadcastChannel` (network, wraps `BroadcastClient`) or `LocalChannel` (single prover, used by `pokprover.cpp` tests). |
| `randomness.hpp` | `FSModule<FieldT>`: Fiat–Shamir transcript. `absorb()` feeds SHA-512; `squeeze()` finalises and reduces the 512-bit digest mod r. A module can be squeezed only once, so a fresh module is used per challenge or the callers re-absorb. |
| `utility.hpp` | Element (de)serialisation helpers, `read_elements_montgomery` (MP-SPDZ share files), `ShamirShare<FieldT, t, n>` / `ShamirShareVec` (evaluation points 1..n, matching MP-SPDZ) |

### Legacy (not used by `run.sh`)

| File | Contents |
|------|----------|
| `pokprover.hpp/.cpp` | Earlier `PoKProver` / `DPoKProver` (Schnorr-style vector PoK plus an interactive log-size variant) and verifiers |
| `bbsauthprover.hpp/.cpp`, `runbbsprover.cpp` | Earlier 3-party flow in which one authenticating prover writes its extended witness (`m, eta, r, v, e, t`) for MP-SPDZ, then all parties run `DPoKProver` |
| `setup.cpp` | Generates params, messages and signatures for the legacy flow |
| `bbs.cpp`, `nipk.cpp` | Micro-benchmarks and tests |

## 4. Wire and file formats

**Hub protocol.**
- A client sends the multipart message `[client_id (1 byte), code, payload, hello]`. The
  ROUTER socket prepends a connection id, so the hub sees 5 frames.
- Codes: `1` connect, `3` hub ACK, `4` client→hub, `5` hub→client.
- After it has received a code-4 message from all `nclients` clients, the hub builds the
  JSON object `{"0": msg_0, "1": msg_1, ...}`, encodes it as BJData, and sends `[5, bundle]`
  to every client.
- **The hub parses every payload as BJData,** so payloads must be BJData-encoded JSON.
  The legacy provers send raw strings and do not work with the current hub.

**Protocol messages.** JSON objects encoded with `json::to_bjdata`. Group and field
elements are stored as strings produced by libff's `operator<<` (see `ToString`).

**Element serialisation.** libff is built with its defaults (`BINARY_OUTPUT`,
`MONTGOMERY_OUTPUT`), so G1 points serialise as binary. The project code is compiled
without those flags, so field elements read from text files (messages, signatures)
are decimal.

**MP-SPDZ share files** (`Persistence/Transactions-P<j>.data`):
- An 8-byte little-endian length, followed by a signature of that length (protocol name and prime).
- Then the shares, 32 bytes each, little-endian, in Montgomery form (`x·2^256 mod r`).
- `read_elements_montgomery` skips the header and multiplies each share by `2^{-256}`.
- `bbs_share.mpc` writes party 0's n shares first, then party 1's, and so on.

## 5. Known limitations

Proof-of-concept caveats to keep in mind when reading or extending the code:

- **Not a complete verifier.**
  - The final pairing check `e(A', vk) = e(Ā, g2)` and the check `C + D = −g1` are left as
    `@todo` in `run_interactive_phase_private`. The status reports only the DPOKs.
  - In the loops over the C and A proofs, `status_C` and `status_A` are overwritten on every
    iteration, so only the last party's result counts toward the final status.
- **Trusted dealer.** Only the message shares come from MP-SPDZ. The shares of `e, r, v, t, eta`
  and all signatures are produced in-process by `test_dpok_bbs_mp_spdz`, and every prover thread
  sees the dealer's data.
- **Single machine.** The hub address (`localhost:8000`) and N = 5 are hard-coded.
- **Fiat–Shamir hashing.** In `FSModule::absorb(const std::string&)`, `(2^j)` is XOR rather than
  a power, so bytes are packed into words lossily. Provers stay consistent with each other, but
  the transcript hash is weaker than intended.

## 6. Where to start reading

1. `dpok-bbs.cpp` → `main` and `test_dpok_bbs_mp_spdz`: how inputs are prepared.
2. `dpok-bbs.hpp` → `run_interactive_phase_private`: the protocol, top to bottom.
3. `dpok-dlog.hpp` → `run_interactive_phase_private`: one distributed PoK.
4. `nipk.hpp`: the non-interactive proof that each DPOK uses.
5. `bulletinboard.hpp` → `broadcastclient.hpp` → `broadcasthub.hpp`: the networking.

//
// Created by nitin on 19/8/23.
//

#ifndef AUTH_MPC_DPOK_DLOG_HPP
#define AUTH_MPC_DPOK_DLOG_HPP

#include <libff/algebra/field_utils/bigint.hpp>
#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libff/algebra/scalar_multiplication/wnaf.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/rng.hpp>
#include <libff/common/utils.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <iostream>
#include <vector>
#include <fstream>
#include <algorithm>
#include <json.hpp>

#include "randomness.hpp"
#include "bulletinboard.hpp"
#include "nipk.hpp"

using namespace libff;
using std::size_t;

template<typename GroupT, typename FieldT>
struct ProtocolDlogPublicParams {
    std::vector<GroupT> gens;
    std::vector<GroupT> h;
    GroupT k_gen;
    std::vector<FieldT> reconstruct_coefficients;
};

template<typename GroupT, typename FieldT>
struct ProtocolDlogProverInput {
    std::vector<FieldT> ss;     // witness vector
    GroupT commitment;          // witness commitment
    FieldT rr;                  // randomness to mask witness
};

template<typename GroupT, typename FieldT>
struct ProtocolDlogWorkerInput {
    std::vector<FieldT> ss;     // shares of witness
    GroupT commitment;          // witness commitment
    FieldT rr;                  // shares of randomness
};

template<typename GroupT, typename FieldT, size_t N>
class ProtocolDlog {
public:
    void set_public_params(const ProtocolDlogPublicParams<GroupT, FieldT>& pp)
    {
        this->public_params = pp;
    };

    void set_prover_input(size_t prover_id, const ProtocolDlogProverInput<GroupT, FieldT>& prover_input)
    {
        this->prover_id = prover_id;
        this->prover_input = prover_input;
    };

    void set_worker_input(size_t worker_id, const ProtocolDlogWorkerInput<GroupT, FieldT>& worker_input)
    {
        this->worker_id = worker_id;
        this->worker_input = worker_input;
    }

    void set_bulletin_board(const BulletinBoard<BroadcastChannel>& bb)
    {
        this->bb = bb;
    };

    bool run_interactive_phase(bool robust = true)
    {
        return run_interactive_phase_private(robust);
    }

private:
    size_t worker_id;
    size_t prover_id;
    ProtocolDlogPublicParams<GroupT, FieldT> public_params;
    ProtocolDlogPublicParams<GroupT, FieldT> prover_input;
    ProtocolDlogWorkerInput<GroupT, FieldT>  worker_input;
    BulletinBoard<BroadcastChannel> bb;
    FSModule<FieldT> fs_module;

    bool run_interactive_phase_private(bool robust);
    bool verify_proof(const Statement<GroupT, FieldT>& statement, const std::string& proof);
};

template<typename GroupT, typename FieldT, size_t N>
bool ProtocolDlog<GroupT, FieldT, N>::run_interactive_phase_private(bool robust) {
    bool status = true;
    // establish connection to the broadcast channel
    //bb.init();

    // commit to shares and randomness
    auto A = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
            public_params.gens.begin(), public_params.gens.end(),
            worker_input.ss.begin(), worker_input.ss.end(),
            1
    );

    json round_1_message;
    round_1_message["A"] = ToString<GroupT>(A);
    std::vector<FieldT> rr;
    GroupT B;
    if (robust) {
        rr.emplace_back(worker_input.rr);
        rr.emplace_back(FieldT::random_element());
        B = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
                public_params.h.begin(), public_params.h.end(),
                rr.begin(), rr.end(),
                1
        );

        round_1_message["B"] = ToString<GroupT>(B);
    }

    auto round_1_message_bytes = json::to_bjdata(round_1_message);
    std::string round_1_byte_string(round_1_message_bytes.begin(), round_1_message_bytes.end());
    bb.publish(round_1_byte_string);

    std::string all_round_1_messages = bb.get_all_messages();
    json round_1_recv_message = json::from_bjdata(all_round_1_messages);
    fs_module.absorb(all_round_1_messages);

    // obtain the challenge vector
    auto gamma = fs_module.squeeze();
    std::vector<FieldT> challenge;
    challenge.emplace_back(gamma);
    std::stringstream ro_stream;
    FSModule<FieldT> RO;
    ro_stream << gamma;
    while (challenge.size() < worker_input.ss.size()) {

        RO.absorb(ro_stream.str());
        FieldT next = RO.squeeze();
        ro_stream << next;
        challenge.emplace_back(next);
    }

    // compute v_i and proofs pi1, pi2 and pi3
    FieldT v = FieldT::zero();
    for (size_t i = 0; i < worker_input.ss.size(); ++i) {
        v = v + (challenge[i] * worker_input.ss[i]);
    }

    if (robust) v = v + rr[0];

    // Now compute the proofs
    Statement<GroupT, FieldT> pok_A{public_params.gens, public_params.k_gen, A,
                                    std::vector<FieldT>(public_params.gens.size(), 0), 0};
    NonInteractiveProof<GroupT, FieldT> nipk_A; // , nipk_B, nipk_C;
    nipk_A.set_statement(pok_A);
    nipk_A.set_witness(worker_input.ss);
    auto proof_A = nipk_A.generate_proof();

    json last_message;
    //last_message["v"] = ToString<FieldT>(v);
    last_message["proofA"] = proof_A;

    std::vector<GroupT> all_gens;
    std::vector<FieldT> linear_form, c_witness;
    GroupT C;
    if (robust) {
        linear_form = challenge;
        linear_form.emplace_back(FieldT::one());
        linear_form.emplace_back(FieldT::zero());
        all_gens = public_params.gens;
        all_gens.insert(all_gens.end(), public_params.h.begin(), public_params.h.end());
        c_witness = worker_input.ss;
        c_witness.insert(c_witness.end(), rr.begin(), rr.end());
        C = A + B;


        Statement<GroupT, FieldT> pok_B{public_params.h, public_params.k_gen, B,
                                        std::vector<FieldT>(public_params.h.size(), 0), 0};
        Statement<GroupT, FieldT> pok_C{all_gens, public_params.k_gen, C, linear_form, v};

        NonInteractiveProof<GroupT, FieldT> nipk_B, nipk_C;
        nipk_B.set_statement(pok_B);
        nipk_B.set_witness(rr);
        nipk_C.set_statement(pok_C);
        nipk_C.set_witness(c_witness);

        auto proof_B = nipk_B.generate_proof();
        auto proof_C = nipk_C.generate_proof();

        //json last_message;
        last_message["v"] = ToString<FieldT>(v);
        // last_message["proofA"] = proof_A;
        last_message["proofB"] = proof_B;
        last_message["proofC"] = proof_C;
    }
    auto round_message = json::to_bjdata(last_message);
    std::string round_message_str(round_message.begin(), round_message.end());

    bb.publish(round_message_str);

    // receive the last message from all and run verification
    auto all_round_2_messages = bb.get_all_messages();
    json round_2_message_recv = json::from_bjdata(all_round_2_messages);

    std::vector<GroupT> commitments_A;

    for(size_t i=0; i < N; ++i) {
        bool st1 = true, st2 = true, st3 = true;
        auto proofs = round_2_message_recv[std::to_string(i)];
        auto A_str = round_1_recv_message[std::to_string(i)]["A"].get<std::string>();
        std::vector<GroupT> Avec = read_elements<GroupT>(A_str);
        commitments_A.emplace_back(Avec[0]);

        Statement<GroupT, FieldT> stA{public_params.gens, public_params.k_gen, Avec[0], std::vector<FieldT>(public_params.gens.size()),0};
        st1 = verify_proof(stA, proofs["proofA"].get<std::string>());

        if (robust) {
            auto B_str = round_1_recv_message[std::to_string(i)]["B"].get<std::string>();
            auto v_str = proofs["v"].get<std::string>();
            std::vector<GroupT> Bvec = read_elements<GroupT>(B_str);
            std::vector<FieldT> vvec = read_elements<FieldT>(v_str);

            Statement<GroupT, FieldT> stB{public_params.h, public_params.k_gen, Bvec[0],
                                          std::vector<FieldT>(public_params.h.size()), 0};
            Statement<GroupT, FieldT> stC{all_gens, public_params.k_gen, Avec[0] + Bvec[0], linear_form, vvec[0]};

            st2 = verify_proof(stB, proofs["proofB"].get<std::string>());
            st3 = verify_proof(stC, proofs["proofC"].get<std::string>());
        }
        //std::cout << "Validity of proofs from party " << i << " is " << (st1 && st2 && st3) << std::endl;
        status = status && (st1 && st2 && st3);
    }

    // check reconstruction equation
    auto reconstructed_commitment = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
            commitments_A.begin(), commitments_A.end(),
            this->public_params.reconstruct_coefficients.begin(), this->public_params.reconstruct_coefficients.end(),
            1
            );

    // std::cout << worker_input.commitment << "||||" << reconstructed_commitment << std::endl;
    status = status && (this->worker_input.commitment == reconstructed_commitment);

    return status;
}

template<typename GroupT, typename FieldT, size_t N>
bool ProtocolDlog<GroupT, FieldT, N>::verify_proof(
        const Statement<GroupT, FieldT>& statement,
        const std::string& proof)
{
    NonInteractiveProofVerifier<GroupT, FieldT> verifier;
    return verifier.verify(statement, proof);
}



#endif //AUTH_MPC_DPOK_DLOG_HPP

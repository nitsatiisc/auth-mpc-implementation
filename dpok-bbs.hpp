//
// Created by nitin on 27/8/23.
//

#ifndef AUTH_MPC_DPOK_BBS_HPP
#define AUTH_MPC_DPOK_BBS_HPP
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

#include "dpok-dlog.hpp"
#include "bbs.hpp"

using namespace libff;
using std::size_t;

// ProtocolBBSProverInput
// ProtocolBBSWorkerInput

// round1: first message randomised signature
// round2: derive challenge and compute the DPOK worker inputs
// run the three DPOK protocols

template<typename ppT>
struct ProtocolBBSPublicParams {
    BBSPublicParams<ppT> bbs_params;
    std::vector<G1<ppT>> extra_gens;
    G2<ppT> bbs_vk;
    G1<ppT> k_gen;
    std::vector<Fr<ppT>> reconstruct_coefficients;
};

template<typename ppT>
struct RandomizedStatement {
    G1<ppT> a_dash;
    G1<ppT> a_bar;
    G1<ppT> d;
    G1<ppT> C;
    G1<ppT> D;
};

template<typename ppT>
struct ProtocolBBSProverInput {
    BBSSignature<ppT> bbs_signature;
    std::vector<Fr<ppT>> message;
    Fr<ppT> u, r, eta;
    std::vector<Fr<ppT>> shares_beta;
    std::vector<Fr<ppT>> shares_r;
    std::vector<Fr<ppT>> shares_v;
    std::vector<Fr<ppT>> shares_t;
    std::vector<Fr<ppT>> shares_eta;
    // shares_message[i] is a vector of size n, containing share of party i's message.
    std::vector< std::vector<Fr<ppT>> > shares_message;
};

template<typename ppT, size_t N>
class ProtocolBBS {
public:
    void set_public_params(const ProtocolBBSPublicParams<ppT>& pp)
    {
        this->public_params = pp;
    };

    void set_prover_input(size_t prover_id, const ProtocolBBSProverInput<ppT>& prover_input)
    {
        this->prover_id = prover_id;
        this->prover_input = prover_input;
    };

    bool run_interactive_phase(bool robust = true)
    {
        return run_interactive_phase_private(robust);
    };

    typedef G1<ppT> GroupT;
    typedef Fr<ppT> FieldT;

private:
    ProtocolBBSPublicParams<ppT> public_params;
    ProtocolBBSProverInput<ppT> prover_input;
    size_t prover_id;
    FSModule<FieldT> fs_module;

    bool run_interactive_phase_private(bool robust);

    RandomizedStatement<ppT> compute_randomized_statement() {
        RandomizedStatement<ppT> randomized_statement;
        auto v = prover_input.u.inverse();
        GroupT b = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
                public_params.bbs_params.h.begin()+1, public_params.bbs_params.h.end(),
                prover_input.message.begin(), prover_input.message.end(),
                1
                ) + public_params.bbs_params.g1 +
                (prover_input.bbs_signature.s * public_params.bbs_params.h[0]);

        GroupT d = (prover_input.u * b) - (prover_input.r * public_params.bbs_params.h[0]);
        FieldT t = prover_input.bbs_signature.s - prover_input.r * v;
        GroupT a_dash = prover_input.u * prover_input.bbs_signature.A;
        GroupT a_bar = (prover_input.u * b) - (prover_input.bbs_signature.e * a_dash);
        GroupT C = (t - prover_input.eta) * public_params.bbs_params.h[0] - (v * d);
        GroupT D =  GroupT::zero() - (C + public_params.bbs_params.g1);

        randomized_statement.a_dash = a_dash;
        randomized_statement.a_bar = a_bar;
        randomized_statement.d = d;
        randomized_statement.C = C;
        randomized_statement.D = D;

        return randomized_statement;

    };

};

template<typename ppT, size_t N>
bool ProtocolBBS<ppT, N>::run_interactive_phase_private(bool robust)
{
    std::string hub_address = "localhost:8000";

    // set up broadcast channel
    BroadcastChannel channel(hub_address, this->prover_id);
    BulletinBoard<BroadcastChannel> bb;
    bb.set_channel(channel);
    bb.init();

    bool status, status_A, status_C;

    // compute first message
    auto randomised_statement = compute_randomized_statement();
    json round_1_message;
    round_1_message["a_dash"] = ToString<GroupT>(randomised_statement.a_dash);
    round_1_message["a_bar"] = ToString<GroupT>(randomised_statement.a_bar);
    round_1_message["d"] = ToString<GroupT>(randomised_statement.d);
    round_1_message["C"] = ToString<GroupT>(randomised_statement.C);
    round_1_message["D"] = ToString<GroupT>(randomised_statement.D);
    auto round_1_message_bytes = json::to_bjdata(round_1_message);
    std::string round_1_byte_string(round_1_message_bytes.begin(), round_1_message_bytes.end());
    bb.publish(round_1_byte_string);

    // receive all first messages
    std::string all_round_1_statements = bb.get_all_messages();
    json all_statements_json = json::from_bjdata(all_round_1_statements);
    fs_module.absorb(all_round_1_statements);

    // compute challenge gamma
    auto gamma = fs_module.squeeze();

    // compute witnesses for DPOK protocols

    // Compute witness y = (\eta_i, m) for the big DPOK protocol.
    FieldT eta = FieldT::zero();
    std::vector<FieldT> message(this->prover_input.message.size(), FieldT::zero());
    for(size_t j=0; j < N; ++j)
    {
        eta = eta + ((gamma^j) * prover_input.shares_eta[j]);
        for(size_t k=0; k < message.size(); ++k)
            message[k] = message[k] + ((gamma^j) * prover_input.shares_message[j][k]);
    }

    std::vector<FieldT> y;
    y.emplace_back(eta);
    y.insert(y.end(), message.begin(), message.end());

    // Compute statement D
    std::vector<GroupT> Dvec;
    for(size_t j=0; j < N; ++j)
    {
        auto Dstr = all_statements_json[std::to_string(j)]["D"].get<std::string>();
        std::vector<GroupT> Delem(1);
        read_elements<GroupT>(Delem, Dstr, 1);
        Dvec.emplace_back(Delem[0]);
    }

    GroupT D = GroupT::zero();
    for(size_t j=0; j < N; ++j)
        D = D + ((gamma^j) * Dvec[j]);

    // call DPOK protocols
    ProtocolDlog<GroupT, FieldT, N> proto_dlog;
    ProtocolDlogPublicParams<GroupT, FieldT> pp_dlog{public_params.bbs_params.h, public_params.extra_gens, public_params.k_gen, public_params.reconstruct_coefficients};
    ProtocolDlogWorkerInput<GroupT, FieldT> wi_dlog{y, D, FieldT::random_element()};
    proto_dlog.set_public_params(pp_dlog);
    proto_dlog.set_bulletin_board(bb);
    proto_dlog.set_worker_input(prover_id, wi_dlog);

    // @todo setup the other small DPOK protocols
    for(size_t i=0; i < N; ++i)
    {
        ProtocolDlog<GroupT, FieldT, N> proto_dlog_C;
        // prepare statement and witness
        auto Cstr = all_statements_json[std::to_string(i)]["C"].get<std::string>();
        auto dstr = all_statements_json[std::to_string(i)]["d"].get<std::string>();
        std::vector<GroupT> Cvec(1), dvec(1);
        read_elements<GroupT>(Cvec, Cstr, 1);
        read_elements<GroupT>(dvec, dstr, 1);
        std::vector<GroupT> gens = {dvec[0], public_params.bbs_params.h[0]};
        std::vector<FieldT> witness = {FieldT(-1)*prover_input.shares_v[i], prover_input.shares_t[i] - prover_input.shares_eta[i]};

        ProtocolDlogPublicParams<GroupT, FieldT> pp_dlog_C{gens, public_params.extra_gens, public_params.k_gen, public_params.reconstruct_coefficients};
        ProtocolDlogWorkerInput<GroupT, FieldT> wi_dlog_C{witness, Cvec[0], FieldT::random_element()};

        proto_dlog_C.set_public_params(pp_dlog_C);
        proto_dlog_C.set_bulletin_board(bb);
        proto_dlog_C.set_worker_input(prover_id, wi_dlog_C);

        status_C = proto_dlog_C.run_interactive_phase(robust);
        //std::cout << "Worker " << prover_id << " output for C protocol " << i << " " << proto_dlog_C.run_interactive_phase() << std::endl;
        //std::cout << prover_id << ":" << "status_C=" << status_C;
    }

    for(size_t i=0; i < N; ++i)
    {
        ProtocolDlog<GroupT, FieldT, N> proto_dlog_A;
        // prepare statement and witness
        std::cout << __LINE__ << std::endl;
        auto a_dash_str = all_statements_json[std::to_string(i)]["a_dash"].get<std::string>();
        auto dstr = all_statements_json[std::to_string(i)]["d"].get<std::string>();
        auto a_bar_str = all_statements_json[std::to_string(i)]["a_bar"].get<std::string>();
        std::vector<GroupT> a_dash_vec(1), dvec(1), a_bar_vec(1);
        read_elements<GroupT>(a_dash_vec, a_dash_str, 1);
        read_elements<GroupT>(dvec, dstr, 1);
        read_elements<GroupT>(a_bar_vec, a_bar_str, 1);
        std::vector<GroupT> gens = {a_dash_vec[0], public_params.bbs_params.h[0]};
        std::vector<FieldT> witness = {FieldT(-1)*prover_input.shares_beta[i], prover_input.shares_r[i]};

        ProtocolDlogPublicParams<GroupT, FieldT> pp_dlog_A{gens, public_params.extra_gens, public_params.k_gen, public_params.reconstruct_coefficients};
        ProtocolDlogWorkerInput<GroupT, FieldT> wi_dlog_A{witness, a_bar_vec[0] - dvec[0], FieldT::random_element()};

        proto_dlog_A.set_public_params(pp_dlog_A);
        proto_dlog_A.set_bulletin_board(bb);
        proto_dlog_A.set_worker_input(prover_id, wi_dlog_A);
        status_A = proto_dlog_A.run_interactive_phase(robust);
        //std::cout << prover_id << ":" << "status_A=" << status_A;
        //std::cout << "Worker " << prover_id << " output for A protocol " << i << " " << proto_dlog_A.run_interactive_phase() << std::endl;
    }


    // output true if all of them output true
    // @todo run additional verification.
    status = proto_dlog.run_interactive_phase(robust);
    //std::cout << prover_id << ":" << "status=" << status << std::endl;
    status = status && (status_A && status_C);

    std::cout << "Prover " << this->prover_id << ": [ " << status << " , " << channel.bytes_sent() <<
        " , " << channel.bytes_received() << " ]" << std::endl;
    return status;

}

#endif //AUTH_MPC_DPOK_BBS_HPP

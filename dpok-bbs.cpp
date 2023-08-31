//
// Created by nitin on 27/8/23.
//

#include <thread>
#include <algorithm>
#include "dpok-bbs.hpp"

template<typename ppT>
struct ProverInput {
    size_t prover_id;
    std::shared_ptr<ProtocolBBSPublicParams<ppT>> public_params;
    ProtocolBBSProverInput<ppT> prover_input;
};

template<typename ppT, size_t N>
void run_prover(const ProverInput<ppT>& input)
{

    ProtocolBBS<ppT, N> prover;
    prover.set_public_params(*input.public_params);
    prover.set_prover_input(input.prover_id, input.prover_input);

    auto status = prover.run_interactive_phase(false);
    std::cout << "Prover " << input.prover_id << " output " << status;


}

template<typename ppT, size_t N>
void test_dpok_bbs_proto()
{
    typedef G1<ppT> GroupT;
    typedef Fr<ppT> FieldT;

    size_t n=3000; // message size
    // ************* Protocol Prep **************************
    // - Sample BBS Params for n
    // - Sample messages
    // - Create BBS signatures
    // - Create shared data
    // - Set prover inputs
    // - run provers
    // ******************************************************
    std::string filename = "./data/example";
    generateParams<ppT>(filename, n);
    auto bbs_params =readPublicParams<ppT>(filename, n);
    auto bbs_full_params = readFullParams<ppT>(filename, n);
    auto bbs_vk = bbs_full_params.keypair.vk;
    GroupT k_gen = GroupT::random_element();
    std::vector<GroupT> extra_gens = {GroupT::random_element(), GroupT::random_element()};


    std::vector<FieldT> u(N), r(N), eta(N);
    std::generate(u.begin(), u.end(), [&] { return FieldT::random_element(); });
    std::generate(r.begin(), r.end(), [&] { return FieldT::random_element(); });
    std::generate(eta.begin(), eta.end(), [&] { return FieldT::random_element(); });



    std::vector<std::vector<FieldT>> messages(N, std::vector<FieldT>(n));
    for(size_t i=0; i < N; ++i) {
        std::generate(messages[i].begin(), messages[i].end(),
                      [&] { return FieldT::random_element(); });
    }

    std::vector<BBSSignature<ppT>> bbs_signatures;
    for(size_t i=0; i < N; ++i)
    {
        BBSSignature<ppT> sig = sign_message<ppT, multi_exp_method_bos_coster>(
                bbs_full_params, messages[i], n);
        bbs_signatures.emplace_back(sig);
    }

    std::map<size_t, std::vector<FieldT>> shares_beta;
    std::map<size_t, std::vector<FieldT>> shares_r;
    std::map<size_t, std::vector<FieldT>> shares_v;
    std::map<size_t, std::vector<FieldT>> shares_t;
    std::map<size_t, std::vector<FieldT>> shares_eta;
    std::map<size_t, std::vector<std::vector<FieldT>>> shares_messages;


    for(size_t i=0; i < N; ++i)
    {
        shares_beta[i] = ShamirShare<FieldT, 1, N>(bbs_signatures[i].e);
        shares_r[i] = ShamirShare<FieldT, 1, N>(r[i]);
        shares_v[i] = ShamirShare<FieldT, 1, N>(u[i].inverse());
        auto t = bbs_signatures[i].s - r[i] * (u[i].inverse());
        shares_t[i] = ShamirShare<FieldT, 1, N>(t);
        shares_eta[i] = ShamirShare<FieldT, 1, N>(eta[i]);
        shares_messages[i] = ShamirShareVec<FieldT, 1, N>(messages[i]);
    }

    // Now compute sharings available with each player
    std::map<size_t, std::vector<FieldT>> sharing_beta;
    std::map<size_t, std::vector<FieldT>> sharing_r;
    std::map<size_t, std::vector<FieldT>> sharing_v;
    std::map<size_t, std::vector<FieldT>> sharing_t;
    std::map<size_t, std::vector<FieldT>> sharing_eta;
    std::map<size_t, std::vector<std::vector<FieldT>>> sharing_messages;

    for(size_t j=0; j < N; ++j) {
        // j denotes the player id for which we are collecting the shares (of all inputs)
        std::vector<FieldT> sh_beta(N), sh_r(N), sh_v(N), sh_t(N), sh_eta(N);
        std::vector<std::vector<FieldT>> sh_messages(N);
        for (size_t i = 0; i < N; ++i) {
            sh_beta[i] = shares_beta[i][j];
            sh_r[i] = shares_r[i][j];
            sh_v[i] = shares_v[i][j];
            sh_t[i] = shares_t[i][j];
            sh_eta[i] = shares_t[i][j];
            sh_messages[i] = shares_messages[i][j];
        }

        sharing_beta[j] = sh_beta;
        sharing_r[j] = sh_r;
        sharing_v[j] = sh_v;
        sharing_t[j] = sh_t;
        sharing_eta[j] = sh_eta;
        sharing_messages[j] = sh_messages;
    }
    //FieldT reconstructed_share = FieldT(3)*sharing_messages[0][0][0] - FieldT(3)*sharing_messages[1][0][0] + FieldT(1)*sharing_messages[2][0][0];
    //assert(reconstructed_share == messages[0][0]);

    std::vector<ProverInput<ppT>> prover_inputs;
    for(size_t i=0; i < N; ++i)
    {
        // @todo Look at this carefully.
        ProtocolBBSProverInput<ppT> bbs_prover_input{
            bbs_signatures[i],
            messages[i],
            u[i],
            r[i],
            eta[i],
            sharing_beta[i],
            sharing_r[i],
            sharing_v[i],
            sharing_t[i],
            sharing_eta[i],
            sharing_messages[i]
        };

        ProtocolBBSPublicParams<ppT> public_params{
                bbs_params,
                extra_gens,
                bbs_vk,
                k_gen,
                //{FieldT(5),FieldT(-10),FieldT(10),FieldT(-5),FieldT(1)}
                {FieldT(3), FieldT(-3), FieldT(1)}
        };

        ProverInput<ppT> prover_input{
            i,
            std::make_shared<ProtocolBBSPublicParams<ppT>>(public_params),
            bbs_prover_input
        };

        prover_inputs.emplace_back(prover_input);
    }

    // run the distributed protocol
    std::vector< std::shared_ptr<std::thread> > players(N);
    for(size_t i=0; i < N; ++i)
        players[i].reset(new std::thread(run_prover<ppT, N>, prover_inputs[i]));

    for(size_t i=0; i < N; ++i)
        players[i]->join();

    std::cout << "All threads exited" << std::endl;
}

template<typename ppT, size_t N>
void test_dpok_bbs_mp_spdz()
{
    typedef G1<ppT> GroupT;
    typedef Fr<ppT> FieldT;

    size_t n=400*10; // message size
    // ************* Protocol Prep **************************
    // - Sample BBS Params for n
    // - Sample messages
    // - Create BBS signatures
    // - Create shared data
    // - Set prover inputs
    // - run provers
    // ******************************************************
    std::string persistence_data_dir = "/home/nitin/work/MP-SPDZ/Persistence/";
    std::string player_data_dir = "/home/nitin/work/MP-SPDZ/Player-Data/";
    std::string filename = "example.dat";

    generateParams<ppT>(filename, n);
    auto bbs_params =readPublicParams<ppT>(filename, n);
    auto bbs_full_params = readFullParams<ppT>(filename, n);
    auto bbs_vk = bbs_full_params.keypair.vk;
    GroupT k_gen = GroupT::random_element();
    std::vector<GroupT> extra_gens = {GroupT::random_element(), GroupT::random_element()};


    std::vector<FieldT> u(N), r(N), eta(N);
    std::generate(u.begin(), u.end(), [&] { return FieldT::random_element(); });
    std::generate(r.begin(), r.end(), [&] { return FieldT::random_element(); });
    std::generate(eta.begin(), eta.end(), [&] { return FieldT::random_element(); });



    std::vector<std::vector<FieldT>> messages(N);
    for(size_t player_id=0; player_id < N; ++player_id)
    {
        std::string player_input_file = player_data_dir + "Input-P" + std::to_string(player_id) + "-0";
        std::ifstream ifile(player_input_file);
        messages[player_id] = read_elements<FieldT>(ifile, n);
        assert(messages[player_id].size() == n);
    }

    /*
    for(size_t i=0; i < N; ++i) {
        std::generate(messages[i].begin(), messages[i].end(),
                      [&] { return FieldT::random_element(); });
    }
    */
    std::vector<BBSSignature<ppT>> bbs_signatures;
    for(size_t i=0; i < N; ++i)
    {
        BBSSignature<ppT> sig = sign_message<ppT, multi_exp_method_bos_coster>(
                bbs_full_params, messages[i], n);
        bbs_signatures.emplace_back(sig);
    }

    std::map<size_t, std::vector<FieldT>> shares_beta;
    std::map<size_t, std::vector<FieldT>> shares_r;
    std::map<size_t, std::vector<FieldT>> shares_v;
    std::map<size_t, std::vector<FieldT>> shares_t;
    std::map<size_t, std::vector<FieldT>> shares_eta;
    std::map<size_t, std::vector<std::vector<FieldT>>> shares_messages;


    for(size_t i=0; i < N; ++i)
    {
        shares_beta[i] = ShamirShare<FieldT, 1, N>(bbs_signatures[i].e);
        shares_r[i] = ShamirShare<FieldT, 1, N>(r[i]);
        shares_v[i] = ShamirShare<FieldT, 1, N>(u[i].inverse());
        auto t = bbs_signatures[i].s - r[i] * (u[i].inverse());
        shares_t[i] = ShamirShare<FieldT, 1, N>(t);
        shares_eta[i] = ShamirShare<FieldT, 1, N>(eta[i]);
        //shares_messages[i] = ShamirShareVec<FieldT, 2, N>(messages[i]);
    }

    // Now compute sharings available with each player
    std::map<size_t, std::vector<FieldT>> sharing_beta;
    std::map<size_t, std::vector<FieldT>> sharing_r;
    std::map<size_t, std::vector<FieldT>> sharing_v;
    std::map<size_t, std::vector<FieldT>> sharing_t;
    std::map<size_t, std::vector<FieldT>> sharing_eta;
    std::map<size_t, std::vector<std::vector<FieldT>>> sharing_messages;

    for(size_t j=0; j < N; ++j) {
        // j denotes the player id for which we are collecting the shares (of all inputs)
        std::vector<FieldT> sh_beta(N), sh_r(N), sh_v(N), sh_t(N), sh_eta(N);
        std::vector<std::vector<FieldT>> sh_messages(N);
        for (size_t i = 0; i < N; ++i) {
            sh_beta[i] = shares_beta[i][j];
            sh_r[i] = shares_r[i][j];
            sh_v[i] = shares_v[i][j];
            sh_t[i] = shares_t[i][j];
            sh_eta[i] = shares_eta[i][j];
            //sh_messages[i] = shares_messages[i][j];
        }

        sharing_beta[j] = sh_beta;
        sharing_r[j] = sh_r;
        sharing_v[j] = sh_v;
        sharing_t[j] = sh_t;
        sharing_eta[j] = sh_eta;
        //sharing_messages[j] = sh_messages;
        // read message shares for party j and reshape it so that sh_messages[i] is an n length
        // vector of shares f message[i]
        std::string shares_file = persistence_data_dir + "Transactions-P" + std::to_string(j)+".data";
        std::cout << shares_file << std::endl;
        std::ifstream ifile(shares_file, std::ios::binary);
        std::vector<FieldT> flattened_shares = read_elements_montgomery<FieldT>(ifile);
        std::cout << flattened_shares.size() << std::endl;
        assert(flattened_shares.size() == N*n);
        for(size_t i=0; i < N; ++i)
            sh_messages[i].insert(sh_messages[i].end(), flattened_shares.begin() + (i*n),
                                  flattened_shares.begin() + (i*n) + n);

        sharing_messages[j] = sh_messages;

    }

    // sanity check on reconstruction of shares
    /*
    for(size_t i=0; i < N; ++i) {
        for (size_t j = 0; j < n; ++j) {
            FieldT reconstructed_share = FieldT(3) * sharing_messages[0][i][j] - FieldT(3) * sharing_messages[1][i][j] +
                                         FieldT(1) * sharing_messages[2][i][j];
            assert(reconstructed_share == messages[i][j]);
        }
    }
    */

    std::vector<ProverInput<ppT>> prover_inputs;
    for(size_t i=0; i < N; ++i)
    {
        // @todo Look at this carefully.
        ProtocolBBSProverInput<ppT> bbs_prover_input{
                bbs_signatures[i],
                messages[i],
                u[i],
                r[i],
                eta[i],
                sharing_beta[i],
                sharing_r[i],
                sharing_v[i],
                sharing_t[i],
                sharing_eta[i],
                sharing_messages[i]
        };

        ProtocolBBSPublicParams<ppT> public_params{
                bbs_params,
                extra_gens,
                bbs_vk,
                k_gen,
                {FieldT(5),FieldT(-10),FieldT(10),FieldT(-5),FieldT(1)}
                //{FieldT(3), FieldT(-3), FieldT(1)},
        };

        ProverInput<ppT> prover_input{
                i,
                std::make_shared<ProtocolBBSPublicParams<ppT>>(public_params),
                bbs_prover_input
        };

        prover_inputs.emplace_back(prover_input);
    }

    // run the distributed protocol
    std::vector< std::shared_ptr<std::thread> > players(N);
    long long start = libff::get_nsec_time();
    for(size_t i=0; i < N; ++i)
        players[i].reset(new std::thread(run_prover<ppT, N>, prover_inputs[i]));

    for(size_t i=0; i < N; ++i)
        players[i]->join();

    long long end = libff::get_nsec_time();

    std::cout << "All threads exited: " << (end - start)/1000000 << " ms" << std::endl;
}



int main(int argc, char *argv[])
{
    typedef alt_bn128_pp ppT;
    typedef Fr<ppT> FieldT;
    typedef G1<ppT> GroupT;

    ppT::init_public_params();
    //test_dpok_bbs_proto<ppT, 3>();
    test_dpok_bbs_mp_spdz<ppT, 5>();

}

//
// Created by nitin on 19/8/23.
//

#include<thread>
#include "dpok-dlog.hpp"

//const size_t N = 5;

template<typename GroupT, typename FieldT>
struct WorkerInput {
    size_t worker_id;
    std::shared_ptr<ProtocolDlogPublicParams<GroupT, FieldT>> public_params;
    ProtocolDlogWorkerInput<GroupT, FieldT> worker_input;
};

template<typename GroupT, typename FieldT, size_t N>
void run_worker(const WorkerInput<GroupT, FieldT>& input)
{
    BulletinBoard<BroadcastChannel> bb;
    std::string hub_address = "localhost:8000";
    BroadcastChannel channel(hub_address, input.worker_id);
    bb.set_channel(channel);
    bb.init();

    ProtocolDlog<GroupT, FieldT, N> worker;
    worker.set_worker_input(input.worker_id, input.worker_input);
    worker.set_public_params(*input.public_params);
    worker.set_bulletin_board(bb);

    auto status = worker.run_interactive_phase();


}

template<typename GroupT, typename FieldT, size_t N>
void test_dpok_dlog_proto()
{
    size_t n=32;
    std::vector<GroupT> gens;
    std::vector<GroupT> h;
    std::vector<FieldT> witness;
    GroupT k_gen;
    GroupT commitment;
    std::vector<FieldT> reconstruction_coeffs {FieldT(5), FieldT(-10), FieldT(10), FieldT(-5), FieldT(1)};

    for(size_t i=0; i < n; ++i)
    {
        gens.emplace_back(GroupT::random_element());
        witness.emplace_back(FieldT::random_element());
    }

    k_gen = GroupT::random_element();
    h.emplace_back(GroupT::random_element());
    h.emplace_back(GroupT::random_element());


    commitment = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
            gens.begin(), gens.end(),
            witness.begin(), witness.end(),
            1
    );

    auto shares = ShamirShareVec<FieldT, 2, N>(witness);
    FieldT r = FieldT::random_element();
    auto rr = ShamirShare<FieldT, 2, N>(r);


    // check recombination
    FieldT reconstructed_r = FieldT::zero();
    for(size_t i=0; i < N; ++i) {
        reconstructed_r = reconstructed_r + (rr[i] * reconstruction_coeffs[i]);
    }

    assert( r == reconstructed_r);

    ProtocolDlogPublicParams<GroupT, FieldT> public_params{gens, h, k_gen, reconstruction_coeffs};
    auto shared_pp = std::make_shared<ProtocolDlogPublicParams<GroupT, FieldT>>(public_params);

    std::vector<WorkerInput<GroupT, FieldT>> worker_inputs;
    for(size_t i=0; i < N; ++i)
    {
        WorkerInput<GroupT, FieldT> worker_input{i, shared_pp, ProtocolDlogWorkerInput<GroupT, FieldT>{shares[i], commitment, rr[i]}};
        worker_inputs.emplace_back(worker_input);
    }

    std::vector< std::shared_ptr<std::thread> > players(N);
    for(size_t i=0; i < N; ++i)
        players[i].reset(new std::thread(run_worker<GroupT,FieldT, N>, worker_inputs[i]));

    for(size_t i=0; i < N; ++i)
        players[i]->join();

    std::cout << "All threads exited" << std::endl;

}

int main(int argc, char *argv[])
{
    typedef alt_bn128_pp ppT;
    typedef Fr<ppT> FieldT;
    typedef G1<ppT> GroupT;

    ppT::init_public_params();
    test_dpok_dlog_proto<GroupT, FieldT, 5>();

}

#include "bbsauthprover.hpp"


const std::string data_dir_prefix = "data/Input-P";
const std::string dest_dir_prefix = "Player-Data/Input-P";
size_t L = 1000;


template<typename GroupT, typename FieldT>
void read_signature(const std::string& filename, GroupT& A, FieldT& e, FieldT& s)
{
    std::ifstream ifile(filename);
    ifile >> A;
    ifile >> e;
    ifile >> s;

    ifile.close();
}

void setup_player(size_t playerid)
{
    alt_bn128_pp::init_public_params();
    typedef libff::G1<alt_bn128_pp> GroupT;
    typedef libff::Fr<alt_bn128_pp> FieldT;

    // read message
    std::string msgfilename = data_dir_prefix + std::to_string(playerid);
    std::string hub_address = "localhost:8000";

    BBSAuthProver<GroupT, FieldT, 3> bbsprover(hub_address, playerid);
    BBSMessage<alt_bn128_pp> msg = readMessage<alt_bn128_pp>(msgfilename, L);
    BBSFullParams<alt_bn128_pp> bbs_pp = readFullParams<alt_bn128_pp>("bbs-public-params", L);

    bbsprover.set_message(msg.m);
    std::vector<GroupT> bbs_gens;
    bbs_gens.emplace_back(bbs_pp.pp.g1);
    bbs_gens.insert(bbs_gens.end(), bbs_pp.pp.h.begin(), bbs_pp.pp.h.end());
    bbsprover.set_bbs_generators(bbs_gens);

    GroupT A;
    FieldT e;
    FieldT s;

    std::string sigfilename = std::string("bbs-signature-P")+std::to_string(playerid)+".sig";
    read_signature<GroupT, FieldT>(sigfilename, A, e, s);
    bbsprover.set_signature(A, e, s);
    bbsprover.set_randomisation(1000, 1000, 1000);

    std::string destfilename = dest_dir_prefix + std::to_string(playerid) + "-0";
    bbsprover.write_extended_witness(destfilename);

}

int main(int argc, char *argv[])
{
    size_t playerid = std::atoi(argv[1]);
    setup_player(playerid);
    return 0;
}
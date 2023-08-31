#include "bbs.hpp"

// generate bbs public params

// generate message files for L = 100, 1000, 10000, 100000

// generate bbs signatures on messages.

//const size_t L = 1023;
// const size_t L = 8191;
// const size_t L = 131071;
const size_t L = 1023;
const std::string msg_file_suffix = "_msg.dat";
const std::string data_dir_prefix = "data/Input-P";
void generate_bbs_params()
{
    alt_bn128_pp::init_public_params();
    generateParams<alt_bn128_pp>("bbs-public-params", L);
}

void generate_msg_file(size_t partyid)
{
    std::string filename = data_dir_prefix + std::to_string(partyid);
    std::ofstream ofile(filename);

    for(size_t i=0; i < L; ++i)
        ofile << (std::rand() % 100) << "\n";

    ofile.close();
}

void generate_bbs_signature(size_t partyid)
{
    alt_bn128_pp::init_public_params();
    std::string filename = data_dir_prefix + std::to_string(partyid);
    std::string sigfilename = std::string("bbs-signature-P")+std::to_string(partyid)+".sig";


    BBSMessage<alt_bn128_pp> msg = readMessage<alt_bn128_pp>(filename, L);
    BBSFullParams<alt_bn128_pp> bbs_pp = readFullParams<alt_bn128_pp>("bbs-public-params", L);
    BBSSignature<alt_bn128_pp> sig = sign<alt_bn128_pp, multi_exp_method_bos_coster>(
        bbs_pp, 
        msg,
        L
    );

    std::ofstream ofile(sigfilename);
    ofile << sig.A; 
    ofile << sig.e << "\n";
    ofile << sig.s << "\n";
    ofile.close();

}

int main(int argc, char *argv[])
{
    generate_bbs_params();
    for(size_t partyid = 0; partyid < 1; ++partyid)
    {
        generate_msg_file(partyid);
        generate_bbs_signature(partyid);
        
    }

    return 0;
}

#include "pokprover.hpp"

using namespace libff;
using std::size_t;

void testPokProver()
{
    alt_bn128_pp::init_public_params();

    typedef alt_bn128_pp ppT;
    typedef G1<ppT> GroupT;
    typedef Fr<ppT> FieldT;

    size_t L = 2;

    PoKProver<GroupT, FieldT, LocalChannel> prover;
    BulletinBoard<LocalChannel> bb;
    std::vector<FieldT> witness;
    GroupT commitment;
    std::vector<GroupT> gens;

    for(size_t i=0; i < L; ++i)
    {
        witness.emplace_back(FieldT::random_element());
        gens.emplace_back(GroupT::random_element());
    }

    commitment = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
        gens.cbegin(), gens.cend(),
        witness.cbegin(), witness.cend(),
        1
    );

    prover.set_bulletin_board(bb);
    prover.set_generators(gens);
    prover.set_witness(witness);
    prover.set_commitment(commitment);

    Transcript tr = prover.run_prover();

    for(auto iter=tr.begin(); iter != tr.end(); ++iter)
    {
        std::cout << iter->first << " : " << iter->second << std::endl;
    }
}


int main(int argc, char *argvp[])
{
    testPokProver();


}
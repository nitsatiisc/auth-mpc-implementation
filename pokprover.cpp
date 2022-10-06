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
    PoKProof<GroupT, FieldT,1> proof = prover.transcript_to_proof<1>(tr, gens.size());
    PoKVerifier<GroupT, FieldT> verifier;
    verifier.set_generators(gens);
    verifier.set_commitment(commitment);
    
    if (verifier.verify(proof)) 
    {
        std::cout << "Verification Status [OK]" << std::endl;
    } else {
        std::cout << "Verification Status [FAIL]" << std::endl;
    }

    /*

    for(auto iter=tr.begin(); iter != tr.end(); ++iter)
    {
        std::cout << iter->first << " : " << iter->second << std::endl;
    }

    std::string fvector = tr[1];
    std::stringstream str;
    char delim;
    str << fvector;
    FieldT v1, v2;
    str >> v1;
    str >> v2;

    std::cout << "z[ 0 ]:" << v1 << std::endl;
    std::cout << "z[ 1 ]:" << v2 << std::endl;
    */

}

void testDPokProver(const char *argv[])
{

    alt_bn128_pp::init_public_params();

    typedef alt_bn128_pp ppT;
    typedef G1<ppT> GroupT;
    typedef Fr<ppT> FieldT;

    std::string hub_address = "localhost:8000";
    size_t client_id = std::atoi(argv[1]);

    size_t L = 2;

    DPoKProver<GroupT, FieldT, 3> dprover(hub_address, client_id);

    std::vector<FieldT> witness0, witness1, witness2, witness;
    GroupT commitment;
    std::vector<GroupT> gens;

    witness0.emplace_back(1); witness0.emplace_back(2);
    witness1.emplace_back(3); witness1.emplace_back(4);
    witness2.emplace_back(5); witness2.emplace_back(6);
    std::vector<FieldT> coeffs = {15, 20};
    gens.emplace_back(coeffs[0] * GroupT::one());
    gens.emplace_back(coeffs[1] * GroupT::one());

    for(size_t i=0; i < L; ++i)
        witness.emplace_back(witness0[i] + witness1[i] + witness2[i]);
    

    commitment = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
        gens.cbegin(), gens.cend(),
        witness.cbegin(), witness.cend(),
        1
    );

    dprover.init();    
    BulletinBoard<BroadcastChannel> bb;
    BroadcastChannel bChannel(hub_address, client_id);
    bb.set_channel(bChannel);
    bb.init();

    dprover.set_bulletin_board(bb);
    dprover.set_generators(gens);
    if (client_id == 0)
        dprover.set_witness(witness0);
    else if (client_id == 1)
        dprover.set_witness(witness1);
    else if (client_id == 2)
        dprover.set_witness(witness2);
    else {};
    
    dprover.set_commitment(commitment);

    Transcript tr = dprover.run_prover();

    {
        PoKProof<GroupT, FieldT, 3> proof = dprover.transcript_to_proof(tr, gens.size());
        std::ofstream ofile(std::string("proof-") + std::string(argv[1]) + ".dat");
        proof.write(ofile);
    };

    PoKProof<GroupT, FieldT, 3> proof(2);
    std::ifstream ifile(std::string("proof-") + std::string(argv[1]) + ".dat");
    proof.read(ifile);


    DPoKVerifier<GroupT, FieldT, 3> verifier;
    verifier.set_generators(gens);
    verifier.set_coefficients(std::vector<FieldT>(3, FieldT::one()));
    verifier.set_commitment(commitment);
    bool ret = verifier.verify(proof);

    if (ret)
        std::cout << "Verification Status [OK]";
    else 
        std::cout << "Verification Status [FAIL]";



}

int main(int argc, const char *argv[])
{
    // testPokProver();
    testDPokProver(argv);
    return 0;


}
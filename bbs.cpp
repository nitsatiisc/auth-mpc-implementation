#include "bbs.hpp"
#include "randomness.hpp"

using namespace libff;
using std::size_t;

int main(int argc, char *argv[])
{
    alt_bn128_pp::init_public_params();
    typedef alt_bn128_pp ppT;
    testReadAndWrite<ppT>();
    testSignAndVerify<ppT>();

    FSModule<Fr<ppT>> fs;
    std::vector<uint64_t> msg = {23, 25, 88};
    fs.absorb(msg);
    fs.squeeze();

    FSModule<Fr<ppT>> fs1;
    fs1.absorb(msg);
    fs1.squeeze();

    return 0;
}
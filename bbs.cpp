#include "bbs.hpp"


using namespace libff;
using std::size_t;

int main(int argc, char *argv[])
{
    alt_bn128_pp::init_public_params();
    typedef alt_bn128_pp ppT;
    testReadAndWrite<ppT>();
    testSignAndVerify<ppT>();
    return 0;
}
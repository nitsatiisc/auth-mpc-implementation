//
// Created by nitin on 16/8/23.
//

#include "nipk.hpp"
using namespace libff;
using std::size_t;

int main(int argc, char *argv[]) {
    alt_bn128_pp::init_public_params();
    typedef alt_bn128_pp ppT;
    typedef Fr<ppT> FieldT;
    typedef G1<ppT> GroupT;

    test_nipk_proof<GroupT, FieldT>();
    return 0;
}


/** @file
 *****************************************************************************

 Implementation of functions for generating randomness.

 See rng.hpp .

 *****************************************************************************
 * @author     This file is part of libff, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef AUTH_MPC_RANDOMNESS_HPP_
#define AUTH_MPC_RANDOMNESS_HPP_

#include <gmp.h>
#include <gmpxx.h>
#include <openssl/sha.h>

#include <libff/algebra/fields/bigint.hpp>
#include <libff/common/rng.hpp>
#include <libff/common/utils.hpp>

using namespace libff;

const char hex_table[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                          '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

std::string hex_string_from_bytes(const unsigned char *bytes, size_t n)
{
    std::string hex_string = "";
    for(size_t i=0; i < n; ++i)
    {
        uint8_t val = bytes[i];
        hex_string.emplace_back(hex_table[val/16]);
        hex_string.emplace_back(hex_table[val % 16]);

    }

    return hex_string;
}

template<typename FieldT>
class FSModule {
    public:
    FSModule() { SHA512_Init(&sha512); };

    private:
    SHA512_CTX sha512;

    public:
    void absorb(std::vector<uint64_t>& msg)
    {
        for(size_t i=0; i < msg.size(); ++i)
        {
            uint64_t idx = msg[i];
            SHA512_Update(&sha512, &idx, sizeof(idx));
        }
    };

    FieldT squeeze()
    {
        unsigned char hash[SHA512_DIGEST_LENGTH];
        SHA512_Final(hash, &sha512);

        // get a bigint equivalent of hash
        // convert hash to hex_string
        auto hex_string = hex_string_from_bytes(hash, sizeof(hash));
        std::cout << hex_string << std::endl;

        // convert hex_string to mpz_t
        // get a bigint equivalent of FieldT::capacity()
        // FieldT::field_char().to_mpz(mpz_t modprime)
        // Get remainder mpz_t 
        // mpz_mod( , , )
        // convert remainder to FieldT
        // get a bigint using from mpz_t
        // get FieldT from bigint.


        return FeildT::zero();

    };



};


#endif 
#ifndef __AUTH_MPC_BBS_HPP__
#define __AUTH_MPC_BBS_HPP__

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <iostream>
#include <vector>
#include <fstream>

using namespace libff;
using std::size_t;



/**
 * @brief Public Parameters: 
 * generators:  
 *   - g_1, h_0,..., h_L: vector over G1
 *   - g_2 : element from G2
 */
template<typename ppT>
class BBSPublicParams
{
    public:
    std::vector< G1<ppT> > h; // h vector
    G1<ppT> g1;
    G2<ppT> g2;
};

/**
 * @brief BBS Keypair
 * x: secret key
 * w: verification key = g_2^x
 * @tparam ppT 
 */
template<typename ppT>
class BBSKeyPair
{
    public:
    Fr<ppT> x;
    G2<ppT> w;
};

/**
 * @brief 
 * 
 * @tparam ppT 
 */
template<typename ppT>
class BBSFullParams
{
    public:
    BBSPublicParams<ppT> pp; 
    BBSKeyPair<ppT> keypair;
};


/**
 * @brief BBS Signature
 * A: G1 element
 * e: Field element
 * s: Field element
 */
template<typename ppT>
class BBSSignature
{
    public:
    G1<ppT> A;
    Fr<ppT> e;
    Fr<ppT> s;
};

/**
 * @brief Generate BBS params and output to file
 * 
 * @tparam ppT 
 * @param filename basename of output files
 * @param L message size
 */
template<typename ppT>
void generateParams(const std::string& filename, size_t L)
{
    std::string ppfilename = filename + "_pp.dat";
    std::string skfilename = filename + "_sk.dat";
    std::string vkfilename = filename + "_vk.dat";

    BBSPublicParams pp;
    pp.g1 = G1<ppT>::random_element();
    for(size_t i=0; i <= L; ++i)
        pp.h.emplace_back(G1<ppT>::random_element());
    
    pp.g2 = G2<ppT>::random_element();

    BBSKeyPair keypair;
    keypair.sk = Fr<ppT>::random_element();
    keypair.vk = (keypair.sk)*pp.g2;

    // write to files
    std::ofstream ppfile(ppfilename);
    ppfile << pp.g1;
    for(size_t i=0; i <= L; ++i)
        ppfile << pp.h[i];
    
    ppfile << pp.g2;

    std::ofstream skfile(skfilename);
    skfile << keypair.sk;

    std::ofstream vkfile(vkfilename);
    vkfile << keypair.vk;

    ppfile.close();
    skfile.close();
    vkfile.close();
}

template<typename ppT>
BBSFullParams<ppT> readFullParams(const std::string& filename, size_t L)
{
    std::string ppfilename = filename + "_pp.dat";
    std::string skfilename = filename + "_sk.dat";
    std::string vkfilename = filename + "_vk.dat";

    BBSFullParams<ppT> params;
    std::ifstream ppfile(ppfilename);
    ppfile >> params.pp.g1;
    for(size_t i=0; i <= L; ++i)
    {
        G1<ppT> elem;
        ppfile >> elem;
        params.pp.h.emplace_back(elem);
    }

    ppfile >> params.pp.g2;

    ppfile.close();

    std::ifstream skfile(skfilename);
    skfile >> params.keypair.sk;
    skfile.close();

    std::ifstream vkfile(vkfilename);
    vkfile >> params.keypair.vk;
    vkfile.close();

    return params;
}

template<typename ppT>
BBSPublicParams<ppT> readPublicParams(const std::string& filename, size_t L)
{
    BBSFullParams<ppT> params = readFullParams(filename, L);
    return params.pp;
}

template<typename ppT>
G2<ppT> readVerificationKey(const std::string& filename)
{
    std::string vkfilename = filename + "_vk.dat";
    G2<ppT> vk; 
    std::ifstream vkfile(vkfilename);
    vkfile >> vk;
    vkfile.close();
    return vk;
}

template<typename ppT>
void testReadAndWrite()
{
    std::string testfile = "test";
    size_t L = 10;

    // generate params
    generateParams<ppT>(testfile, L);

    // read full params
    BBSFullParams<ppT> params = readFullParams<ppT>(testfile, L);

    // check if w = g_2^x
    if (params.keypair.vk == (params.keypair.sk)*(params.pp.g_2))
    {
        std::cout << "Test [OK]" << std::endl;
    } else 
        std::cout << "Test [FAIL]" << std::endl;
}

#endif
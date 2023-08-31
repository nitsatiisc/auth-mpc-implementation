//
// Created by nitin on 16/8/23.
//

#ifndef AUTH_MPC_NIPK_HPP
#define AUTH_MPC_NIPK_HPP

#include <libff/algebra/field_utils/bigint.hpp>
#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libff/algebra/scalar_multiplication/wnaf.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/rng.hpp>
#include <libff/common/utils.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <iostream>
#include <vector>
#include <fstream>
#include <algorithm>
#include <json.hpp>

#include "randomness.hpp"

using namespace libff;
using std::size_t;
using nlohmann::json;

template<typename GroupT, typename FieldT>
struct Statement {
    std::vector<GroupT> gens;
    GroupT k_gen;
    GroupT commitment;
    std::vector<FieldT> linear_form;
    FieldT value;
};

template<typename FieldT> using Witness = std::vector<FieldT>;

template<typename GroupT, typename FieldT>
void write_statement(const Statement<GroupT, FieldT>& statement, std::ostream& ofile)
{
    std::vector<GroupT> group_vec = statement.gens;
    group_vec.push_back(statement.commitment);
    group_vec.push_back(statement.k_gen);
    write_elements(group_vec, ofile, group_vec.size());
    std::vector<FieldT> field_vec = statement.linear_form;
    field_vec.push_back(statement.value);
    write_elements(field_vec, ofile, field_vec.size());
}

template<typename FieldT>
std::vector<FieldT> bits_of(size_t n, size_t logn)
{
    std::vector<FieldT> bits;
    size_t N = n;
    for(size_t i=0; i < logn; ++i)
    {
        if (N % 2)
            bits.emplace_back(FieldT::one());
        else
            bits.emplace_back(FieldT::zero());

        N=N/2;
    }
    std::reverse(bits.begin(), bits.end());

    return bits;
}


template<typename GroupT, typename FieldT>
class NonInteractiveProof {
public:
    NonInteractiveProof() = default;

    /**
     * Set the statement for the non interactive proof.
     * @param statement
     */
    void set_statement(const Statement<GroupT, FieldT>& statement) {
        this->statement = statement;
        // extend the statement size to the power of 2 with G::zero()

        if (ceil(std::log2(this->statement.gens.size())) != floor(std::log2(this->statement.gens.size())))
        {
            size_t next_pow = ceil(std::log2(this->statement.gens.size()));
            auto new_size = 1 << next_pow;
            this->statement.gens.resize(new_size, GroupT::zero());
            this->statement.linear_form.resize(new_size, FieldT::zero());
        }
    };

    /**
     * Set the witness for the proof
     * Should be called after set_statement
     * @param witness
     */
    void set_witness(const Witness<FieldT>& witness)
    {
        this->witness = witness;
        this->witness.resize(this->statement.gens.size(), FieldT::zero());

    };

    /**
     * Outputs a Fiat-Shamir non-interactive proof
     * @return
     */
    std::string generate_proof() {

        std::string proof;

        auto g = this->statement.gens;
        auto s = this->witness;
        auto p = this->statement.commitment;
        auto k = this->statement.k_gen;
        auto L = this->statement.linear_form;
        auto y = this->statement.value;


        if (g.size() != s.size())
        {
            std::cerr << "Generators size does not match witness size";
            exit(-1);
        }
        if (ceil(std::log2(s.size())) != floor(std::log2(s.size())))
        {
            std::cerr << "Witness size is not a power of 2";
            exit(-1);
        }

        std::stringstream statement_str;
        write_statement(this->statement, statement_str);
        fs_module.absorb(statement_str.str());

        std::stringstream proof_str;

        // first challenge to handle the linear form
        FieldT c = fs_module.squeeze();
        for(size_t i=0; i < L.size(); ++i)
            L[i] = c * L[i];

        y = c * y;


        while (g.size() > 1)
        {
            size_t n = g.size();
            // compute garbage cross terms
            std::vector<GroupT> gL(g.begin(), g.begin() + n/2);
            std::vector<GroupT> gR(g.begin()+n/2, g.end());
            std::vector<FieldT> sL(s.begin(), s.begin() + n/2);
            std::vector<FieldT> sR(s.begin() + n/2, s.end());
            std::vector<FieldT> LL(L.begin(), L.begin()+n/2);
            std::vector<FieldT> LR(L.begin()+n/2, L.end());

            std::vector<GroupT> round_messages;

            GroupT b = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
                    gL.begin(), gL.end(),
                    sR.begin(), sR.end(),
                    1);

            GroupT a = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
                    gR.begin(), gR.end(),
                    sL.begin(), sL.end(),
                    1);

            FieldT LR_SL, LL_SR = FieldT::zero();
            // compute the cross products
            for(size_t i=0; i < n/2; ++i) {
                LR_SL += (LR[i] * sL[i]);
                LL_SR += (LL[i] * sR[i]);
            }

            // adjust the a and b terms
            a = a + (LR_SL * k);
            b = b + (LL_SR * k);

            // add a and b to the proof
            round_messages.emplace_back(a);
            round_messages.emplace_back(b);
            write_elements<GroupT>(round_messages, proof_str, round_messages.size());

            // derive challenge
            fs_module.absorb(proof_str.str());
            FieldT c = fs_module.squeeze();


            g.clear();
            s.clear();
            L.clear();

            for(size_t i=0; i < n/2; ++i)
            {
                g.emplace_back(c*gL[i] + gR[i]);
                s.emplace_back(sL[i] + c*sR[i]);
                L.emplace_back(c*LL[i] + LR[i]);
            }
        }

        // Now we simply append the remaining element of s vector to the proof.
        write_elements<FieldT>(s, proof_str, s.size());
        proof = proof_str.str();

        return proof;
    };

private:
    FSModule<FieldT> fs_module;
    Statement<GroupT, FieldT> statement;
    Witness<FieldT> witness;

};

template<typename GroupT, typename FieldT>
class NonInteractiveProofVerifier {
public:
    bool verify(const Statement<GroupT, FieldT>& statement, const std::string& proof) const {

        auto g = statement.gens;
        auto p = statement.commitment;
        auto L = statement.linear_form;
        auto y = statement.value;
        auto k = statement.k_gen;



        if (ceil(std::log2(g.size())) != floor(std::log2(g.size())))
        {
            size_t next_pow = ceil(std::log2(g.size()));
            auto new_size = 1 << next_pow;
            g.resize(new_size, GroupT::zero());
            L.resize(new_size, FieldT::zero());
        }

        auto resized_statement = statement;
        resized_statement.gens = g;
        resized_statement.linear_form = L;

        size_t n = g.size();
        FSModule<FieldT> fs_module;
        std::stringstream statement_str;
        write_statement<GroupT>(resized_statement, statement_str);
        fs_module.absorb(statement_str.str());

        FieldT c = fs_module.squeeze();
        for(size_t i=0; i < L.size(); ++i)
            L[i] = c * L[i];

        y = c*y;
        p = p + (y*k);

        std::vector<GroupT> A, B;
        std::vector<FieldT> C;
        std::stringstream proof_str_verifier;

        std::stringstream proof_str;
        proof_str << proof;

        size_t rounds = log2(g.size());

        for(size_t i=0; i < rounds; ++i)
        {
            std::vector<GroupT> round_AB = read_elements<GroupT>(proof_str, 2);
            A.emplace_back(round_AB[0]);
            B.emplace_back(round_AB[1]);

            write_elements<GroupT>(round_AB, proof_str_verifier, 2);
            fs_module.absorb(proof_str_verifier.str());
            auto c = fs_module.squeeze();
            C.emplace_back(c);
        }

        // read the last message
        std::vector<FieldT> last_message = read_elements<FieldT>(proof_str, 1);
        auto s = last_message[0];

        // compute final generator in terms of initial generators
        std::vector<FieldT> re_comb_G;
        for(size_t i=0; i < n; ++i)
        {
            std::vector<FieldT> bits = bits_of<FieldT>(i, log2(n));
            FieldT prod = FieldT::one();
            for(size_t j=0; j < bits.size(); ++j)
                if (bits[j] == FieldT::zero()) prod = prod * C[j];

            re_comb_G.emplace_back(prod);
        }

        std::vector<FieldT> re_comb_A;
        for(size_t i=0; i < log2(n); ++i)
        {
            FieldT prod = FieldT::one();
            for(size_t j=i+1; j < log2(n); ++j)
                prod = prod * C[j];

            re_comb_A.emplace_back(prod);

        }

        FieldT exp_P = FieldT::one();
        for(size_t i=0; i < log2(n); ++i)
            exp_P = exp_P * C[i];

        std::vector<FieldT> re_comb_B;
        for(size_t i=0; i < log2(n); ++i)
        {
            FieldT prod = FieldT::one();
            for(size_t j=i; j < log2(n); ++j) {
                prod = prod * C[j];
            }
            prod = prod * C[i];

            re_comb_B.emplace_back(prod);
        }

        GroupT G = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
                        g.begin(), g.end(),
                        re_comb_G.begin(), re_comb_G.end(),
                        1
                );
        GroupT rhs = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
                        A.begin(), A.end(),
                        re_comb_A.begin(), re_comb_A.end(),
                        1
                    );
        rhs = rhs + multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
                    B.begin(), B.end(),
                    re_comb_B.begin(), re_comb_B.end(),
                    1
                );
        rhs = rhs + (exp_P * p);

        // compute the final linear form
        FieldT coeff_L = FieldT::zero();
        for(size_t i=0; i < n; ++i)
            coeff_L += (re_comb_G[i]*L[i]);

        GroupT lhs = s*G + (coeff_L * s)*k;

        return (lhs == rhs);
    };

};

template<typename GroupT, typename FieldT>
void test_nipk_proof()
{
    size_t n=1021;
    std::vector<GroupT> gens;
    std::vector<FieldT> witness;
    std::vector<FieldT> linear_form;
    GroupT commitment;
    FieldT value = FieldT::zero();

    for(size_t i=0; i < n; ++i)
    {
        gens.emplace_back(GroupT::random_element());
        witness.emplace_back(FieldT::random_element());
        linear_form.emplace_back(FieldT::one());
    }

    commitment = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
            gens.begin(), gens.end(),
            witness.begin(), witness.end(),
            1
            );

    for(size_t i=0; i < n; ++i)
    {
        value += linear_form[i]*witness[i];
    }

    GroupT k_gen = GroupT::random_element();


    Statement<GroupT, FieldT> statement{gens, k_gen, commitment, linear_form, value};
    NonInteractiveProof<GroupT, FieldT> nipk;
    nipk.set_statement(statement);
    nipk.set_witness(witness);
    auto proof = nipk.generate_proof();

    std::cout << "Proof size: " << proof.size() << " bytes" << std::endl;
    NonInteractiveProofVerifier<GroupT, FieldT> verifier;
    std::cout << verifier.verify(statement, proof) << std::endl;

}

template<typename GroupT, typename FieldT>
void test_nipk_multiple_proofs_parsing()
{
    size_t n=1024;
    std::vector<GroupT> gens;
    std::vector<FieldT> witness1;
    std::vector<FieldT> linear_form1;
    GroupT commitment1;

    std::vector<FieldT> witness2;
    std::vector<FieldT> linear_form2;
    GroupT commitment2;


    FieldT value1, value2 = FieldT::zero();

    for(size_t i=0; i < n; ++i)
    {
        gens.emplace_back(GroupT::random_element());

        witness1.emplace_back(FieldT::random_element());
        witness2.emplace_back(FieldT::random_element());

        linear_form1.emplace_back(FieldT::one());
        linear_form2.emplace_back(FieldT::one());
    }

    commitment1 = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
            gens.begin(), gens.end(),
            witness1.begin(), witness1.end(),
            1
    );

    commitment2 = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
            gens.begin(), gens.end(),
            witness2.begin(), witness2.end(),
            1
    );


    for(size_t i=0; i < n; ++i)
    {
        value1 += linear_form1[i]*witness1[i];
        value2 += linear_form2[i]*witness2[i];
    }

    GroupT k_gen = GroupT::random_element();


    Statement<GroupT, FieldT> statement1{gens, k_gen, commitment1, linear_form1, value1};
    Statement<GroupT, FieldT> statement2{gens, k_gen, commitment2, linear_form2, value2};
    NonInteractiveProof<GroupT, FieldT> nipk1, nipk2;
    nipk1.set_statement(statement1);
    nipk1.set_witness(witness1);
    auto proof1 = nipk1.generate_proof();

    nipk2.set_statement(statement2);
    nipk2.set_witness(witness2);
    auto proof2 = nipk2.generate_proof();

    json two_proofs;
    two_proofs["proof1"] = proof1;
    two_proofs["proof2"] = proof2;

    std::stringstream proof_str;
    proof_str << two_proofs;

    std::cout << proof_str.str() << std::endl;

    json proofs_recv = json::parse(proof_str.str());

    //std::cout << "Proof size: " << proof.size() << " bytes" << std::endl;
    NonInteractiveProofVerifier<GroupT, FieldT> verifier;
    std::cout << verifier.verify(statement1, proofs_recv["proof1"]) << std::endl;
    std::cout << verifier.verify(statement2, proofs_recv["proof2"]) << std::endl;

}
#endif //AUTH_MPC_NIPK_HPP

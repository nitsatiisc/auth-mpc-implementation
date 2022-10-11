#ifndef __AUTH_MPC_POK_PROVER__
#define __AUTH_MPC_POK_PROVER__

#include "bbs.hpp"
#include "randomness.hpp"
#include "bulletinboard.hpp"
#include <memory>

typedef std::map<size_t, std::string>  Transcript;

template<typename T>
void read_elements(std::vector<T>& v, const std::string& s, size_t n)
{
    std::stringstream str;
    str << s;

    for(size_t i=0; i < n; ++i)
    {
        str >> v[i];
    }
}

template<typename T>
std::vector<T> read_elements(std::istream& ifile)
{
    std::vector<T> elements;
    T elem;
    while (ifile >> elem)
        elements.emplace_back(elem);
    
    return elements;
}


template<typename FieldT>
std::vector<FieldT> read_elements_montgomery(std::istream& is)
{
    // precompute powers (2^(8*i)) for i=0,...,31
    std::vector<FieldT> powers_of_two;
    powers_of_two.emplace_back(FieldT::one());
    FieldT power = FieldT::one();
    for(size_t i=0; i < 32; ++i)
    {
        power = FieldT(256)*power;
        powers_of_two.emplace_back(power);
    }

    // Montgomery factor
    size_t nwords = (FieldT::num_bits + 63)/64;
    size_t nbytes = 8 * nwords;
    FieldT R = (FieldT(2))^(64*nwords);
    FieldT Rinv = R.inverse();

    std::vector<FieldT> result;
    std::vector<uint8_t> buffer(nbytes);
    while (!is.eof())
    {
        // read a buffer for the number
        is.read((char *)(&buffer[0]), nbytes);
        if (!is.eof())
        {
            FieldT number = 0;
            for(size_t i=0; i < nbytes; ++i)
                number += (FieldT(buffer[i])*powers_of_two[i]);
            number = number * Rinv;
            result.emplace_back(number);
        }
    }

    return result;

}


/**
 * @brief Distributed POK Proof with n provers
 * 
 * @tparam GroupT 
 * @tparam FieldT 
 * @tparam n 
 */
template<typename GroupT, typename FieldT, size_t n>
class PoKProof {
    public:
    std::vector<GroupT> A;  
    FieldT c; 
    std::vector<std::vector<FieldT>> zz;
    size_t vecsize;

    PoKProof(size_t vsize)
    {
        vecsize = vsize;
        A.resize(n);
        zz.resize(n, std::vector<FieldT>(vecsize));
    };
    

    void write(std::ofstream& ofile) {
        for(size_t i=0; i < n; ++i)
            ofile << A[i];
        
        ofile << c << "\n"; 

        for(size_t i=0; i < n; ++i) 
            for(size_t j=0; j < zz[i].size(); ++j)
                ofile << zz[i][j] << "\n";
    };

    void read(std::ifstream& ifile) {
        for(size_t i=0; i < n; ++i)
            ifile >> A[i];

        ifile >> c;

        for(size_t i=0; i < n; ++i)
        {
            for(size_t j=0; j < vecsize; ++j)
                ifile >> zz[i][j];
        }
    };


};

template<typename GroupT, typename FieldT, typename ChannelT>
class PoKProver 
{
    public:
    PoKProver() { round_ = 0; num_bytes_sent_ = 0; prover_time_ = 0; };
    void set_bulletin_board(const BulletinBoard<ChannelT>& bb) { bb_ = bb; };
    void set_generators(const std::vector<GroupT>& gens) { gens_ = gens; };
    void set_witness(const std::vector<FieldT>& witness) { witness_ = witness; };
    void set_commitment(const GroupT& commitment) { commitment_ = commitment; };
    size_t get_communication() { return num_bytes_sent_; };
    long long get_prover_time() { return prover_time_; };
    void set_coefficients(const std::vector<FieldT>& coeffs) { this->coeffs = coeffs; };

   
    Transcript run_prover()
    {
        std::string m;
        Transcript tr;
        long long start = libff::get_nsec_time();
        while ((m=next_message()) != "")
        {
            bb_.publish(m);
            num_bytes_sent_ += m.size();
            current_msg = bb_.get_all_messages();
            //std::cout << seed << std::endl;
            tr[round_ - 1] = current_msg;
            fs_.absorb(current_msg); // update local state for generating challenges
        }
        long long end = libff::get_nsec_time();
        prover_time_ = end - start;
        return tr;

    };

    // output the result in case of log protocol
    bool get_result() { return result; };

    template<size_t N>
    PoKProof<GroupT, FieldT, N> transcript_to_proof(Transcript& tr, size_t vecsize)
    {
       
        FSModule<FieldT> fs;
        PoKProof<GroupT, FieldT, N> proof(vecsize);
       
        read_elements<GroupT>(proof.A, tr[0], proof.A.size());
        fs.absorb(tr[0]);
        proof.c = fs.squeeze();

        std::vector<FieldT> all_z_vectors(N*vecsize);
        read_elements<FieldT>(all_z_vectors, tr[1], all_z_vectors.size());

        for(size_t i=0; i < proof.zz.size(); ++i)
            for(size_t j=0; j < proof.zz[i].size(); ++j)
                proof.zz[i][j] = all_z_vectors[i*vecsize + j];

        return proof;
    };


    private:
    FSModule<FieldT> fs_;
    std::vector<GroupT> gens_;
    std::vector<FieldT> witness_;
    GroupT commitment_;
    BulletinBoard<ChannelT> bb_;
    std::string current_msg;

    std::vector<FieldT> random_vector_;
    GroupT first_message_;
    size_t round_;
    size_t num_bytes_sent_;
    long long prover_time_;

    // inputs for log protocol
    std::vector<FieldT> coeffs;
    GroupT comm_z;
    GroupT comm_A, comm_B;
    std::vector<GroupT> gens_iter;
    std::vector<FieldT> witness_iter;
    std::vector<GroupT> gens_L, gens_R;
    bool retval;
    bool expect_field_vector;


    private:
    std::string next_message() {
        std::string msg = get_next_message();
        return msg;
    };

    std::string get_all_messages_for_round()
    {
        return bb_.get_all_messages();
    };


    std::string get_next_message() { 

        if (round_ == 0)
        {
            // sample random vector 
            for(size_t i=0; i < witness_.size(); ++i)
                random_vector_.emplace_back(FieldT::random_element());
            
            // compute commitment to the vector
            first_message_ = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
                gens_.cbegin(), gens_.cend(),
                random_vector_.cbegin(), random_vector_.cend(), 1);
            
            std::stringstream str;
            str << first_message_;
            round_++;
            return str.str();
            
        } else if (round_ == 1)
        {
            // compute the challenge
            FieldT c = fs_.squeeze();
            std::vector<FieldT> z(random_vector_.size());
            for(size_t i=0; i < z.size(); ++i)
                z[i] = c*witness_[i] + random_vector_[i];
            
            std::stringstream str;
            for(size_t i=0; i < z.size(); ++i) {
                str << z[i] << "\n";
            }

            round_++;
            return str.str();

        } else if (round_ > 1) 
            return "";

        return "";

    };

    std::string get_next_message_log()
    {
        if (round_ == 0)
        {
            // sample random vector 
            for(size_t i=0; i < witness_.size(); ++i)
                random_vector_.emplace_back(FieldT::random_element());
            
            // compute commitment to the vector
            first_message_ = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
                gens_.cbegin(), gens_.cend(),
                random_vector_.cbegin(), random_vector_.cend(), 1);
            
            std::stringstream str;
            str << first_message_;
            round_++;
            return str.str();
            
        } else if (round_ == 1)
        {
            expect_field_vector = false;
            // compute the challenge and obtain statement for CSP
            FieldT c = fs_.squeeze();
            std::stringstream current(current_msg);
            std::vector<GroupT> A = read_elements<GroupT>(current);
            assert(A.size() == coeffs.size());
            // new statement for CSP
            comm_z = c*commitment_ + multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
                A.cbegin(), A.cend(),
                coeffs.cbegin(), coeffs.cend(),
                1
            );
            // new generators for CSP
            gens_iter = gens_;

            // new witness for CSP
            for(size_t i=0; i < witness_.size(); ++i)
            {
                witness_iter.emplace_back(c*witness_[i] + random_vector_[i]);
            }

            // construct message for this round
            assert(witness_iter.size() % 2 == 0);
            size_t half = witness_iter.size()/2;
            std::vector<FieldT> witness_L(witness_iter.begin(), witness_iter.begin() + half);
            std::vector<FieldT> witness_R(witness_iter.begin()+half, witness_iter.end());
            std::vector<GroupT> gens_L(gens_iter.begin(), gens_iter.begin()+half);
            std::vector<GroupT> gens_R(gens_iter.begin()+half, gens_iter.end());

            GroupT comm_A = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
                gens_L.cbegin(), gens_L.cend(),
                witness_R.cbegin(), witness_R.cend(),
                1
            );

            GroupT comm_B = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
                gens_R.cbegin(), gens_R.cend(),
                witness_L.cbegin(), witness_L.cend(),
                1
            );

            std::stringstream message_stream;
            message_stream << comm_A << comm_B;
            round_++;
            return message_stream.str();

        } else if ((round_ > 1) && (expect_field_vector == false)) {
            // run log protocol
            FieldT c = fs_.squeeze();
            // parse current message for commitments
            std::vector<GroupT> comms_AB = read_elements(std::stringstream(current_msg));
            assert(comms_AB.size() % 2 == 0);
            assert((comms_AB.size()/2) == coeffs.size());
             // A_1,B_1,....,A_n,B_n
             // k_1,c^2k_1,..k_n, c^2k_n
             std::vector<FieldT> coeffs_AB;
             for(size_t i=0; i < coeffs.size(); ++i)
             {
                 coeffs_AB.emplace_back(coeffs[i]);
                 coeffs_AB.emplace_back(coeffs[i]*c.square());
             }

             GroupT comm_z_new = (c*comm_z) + multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
                comms_AB.cbegin(), comms_AB.cend(),
                coeffs_AB.cbegin(), coeffs_AB.cend(),
                1
            );

            assert(witness_iter.size() % 2 == 0);
            size_t half = witness_iter.size()/2;
            std::vector<FieldT> witness_iter_new(half);
            std::vector<GroupT> gens_iter_new(half);
            for(size_t i=0; i < half; ++i)
            {
                witness_iter_new[i] = witness_iter[i] + (c*witness_iter[i+half]);
                gens_iter_new[i] = c*gens_iter[i] + gens_iter[i+half];
            }

            witness_iter = witness_iter_new;
            gens_iter = gens_iter_new;
            comm_z = comm_z_new;

            // check if the size is small enough now
            // if yes, terminate and set result
            if (witness_iter.size() < 128) {
                
            }

            // construct message for this round
            assert(witness_iter.size() % 2 == 0);
            half = witness_iter.size()/2;
            std::vector<FieldT> witness_L(witness_iter.begin(), witness_iter.begin() + half);
            std::vector<FieldT> witness_R(witness_iter.begin()+half, witness_iter.end());
            std::vector<GroupT> gens_L(gens_iter.begin(), gens_iter.begin()+half);
            std::vector<GroupT> gens_R(gens_iter.begin()+half, gens_iter.end());

            GroupT comm_A = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
                gens_L.cbegin(), gens_L.cend(),
                witness_R.cbegin(), witness_R.cend(),
                1
            );

            GroupT comm_B = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
                gens_R.cbegin(), gens_R.cend(),
                witness_L.cbegin(), witness_L.cend(),
                1
            );

            std::stringstream message_stream;
            message_stream << comm_A << comm_B;
            round_++;
            return message_stream.str();
            


        }

    }
};

template<typename GroupT, typename FieldT, size_t n>
class DPoKProver 
{
    public:
    DPoKProver()
    {
        //pchannel.reset(new BroadcastChannel(hub_address, client_id));
    };

    void init() 
    {
        // pchannel->init();
    };

    // delegate these to the internal prover object
    void set_bulletin_board(const BulletinBoard<BroadcastChannel>& bb) { 
        prover.set_bulletin_board(bb); 
    };

    void set_generators(const std::vector<GroupT>& gens) { 
        prover.set_generators(gens); 
    };

    void set_witness(const std::vector<FieldT>& witness) { 
        prover.set_witness(witness); 
    };

    void set_commitment(const GroupT& commitment) { 
        prover.set_commitment(commitment); 
    };

    size_t get_communication() {
        return prover.get_communication();
    };

    long long get_prover_time() {
        return prover.get_prover_time();
    };

    Transcript run_prover()
    {
        return prover.run_prover();
    };

    PoKProof<GroupT, FieldT, n> transcript_to_proof(Transcript& tr, size_t vecsize)
    {
        return prover.template transcript_to_proof<n>(tr, vecsize);
    };


    private:
    PoKProver<GroupT, FieldT, BroadcastChannel> prover;
};


template<typename GroupT, typename FieldT>
class PoKVerifier
{
    private:
    std::vector<GroupT> gens_;
    GroupT commitment_;

    public:
    PoKVerifier() {

    };

    void set_generators(const std::vector<GroupT>& gens) { gens_ = gens; };
    void set_commitment(const GroupT& commitment) { commitment_ = commitment; };

    bool verify(const PoKProof<GroupT, FieldT, 1>& proof)
    {
        // check <gens, z> = c*commitment + A
        GroupT lhs = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
            gens_.begin(), gens_.end(),
            proof.zz[0].begin(), proof.zz[0].end(),
            1
        );

        std::cout << "c = " << proof.c << std::endl;
        GroupT rhs = proof.c * commitment_ + proof.A[0];

        return (rhs == lhs);
    };



};

template<typename GroupT, typename FieldT, size_t n>
class DPoKVerifier
{
    private:
    std::vector<GroupT> gens_;
    GroupT commitment_;
    std::vector<FieldT> coeffs_; // reconstruction coefficients
    long long verifier_time_;

    public:
    DPoKVerifier() {
        verifier_time_ = 0;
    };

    void set_coefficients(const std::vector<FieldT>& coeffs) { coeffs_ = coeffs; };
    void set_generators(const std::vector<GroupT>& gens) { gens_ = gens; };
    void set_commitment(const GroupT& commitment) { commitment_ = commitment; };
    long long get_verifier_time() { return verifier_time_; };

    bool verify(const PoKProof<GroupT, FieldT, n>& proof)
    {
        // check <gens, c_1z_1+c_2z_2+...+c_nz_n> = c*commitment + c_1A_1 + ... + c_nA_n

        long long start = libff::get_nsec_time();
        std::vector<FieldT> z(gens_.size(), FieldT::zero());
        for(size_t i=0; i < z.size(); ++i)
        {
            for(size_t j=0; j < n; ++j)
                z[i] = z[i] + (coeffs_[j] * proof.zz[j][i]);
        }

        std::vector<FieldT> coeffs_rhs;
        coeffs_rhs.emplace_back(proof.c);
        coeffs_rhs.insert(coeffs_rhs.end(), coeffs_.begin(), coeffs_.end());

        std::vector<GroupT> comms_rhs;
        comms_rhs.emplace_back(commitment_);
        comms_rhs.insert(comms_rhs.end(), proof.A.begin(), proof.A.end());

        GroupT lhs = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
            gens_.begin(), gens_.end(),
            z.begin(), z.end(),
            1
        );

        GroupT rhs = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
            comms_rhs.begin(), comms_rhs.end(),
            coeffs_rhs.begin(), coeffs_rhs.end(),
            1
        );

        long long end = libff::get_nsec_time();
        verifier_time_ = end - start;
        return (rhs == lhs);
    };



};
#endif
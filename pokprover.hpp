#ifndef __AUTH_MPC_POK_PROVER__
#define __AUTH_MPC_POK_PROVER__

#include "bbs.hpp"
#include "randomness.hpp"
#include "bulletinboard.hpp"


template<typename GroupT, typename FieldT, typename ChannelT>
class PoKProver 
{
    public:
    PoKProver() { round_ = 0; }
    void set_bulletin_board(const BulletinBoard<ChannelT>& bb) { bb_ = bb; };
    void set_generators(const std::vector<GroupT>& gens) { gens_ = gens; };
    void set_witness(const std::vector<FieldT>& witness) { witness_ = witness; };
    void set_commitment(const GroupT& commitment) { commitment_ = commitment; };
    
    Transcript run_prover()
    {
        std::string m;
        while ((m=next_message()) != "")
        {
            bb_.publish(m);
            std::string seed = get_all_messages_for_round();
            fs_.absorb(seed); // update local state for generating challenges
        }

        return bb_.get_full_transcript();

    };

    private:
    FSModule<FieldT> fs_;
    std::vector<GroupT> gens_;
    std::vector<FieldT> witness_;
    GroupT commitment_;
    BulletinBoard<ChannelT> bb_;
    
    std::vector<FieldT> random_vector_;
    GroupT first_message_;
    size_t round_;

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
            for(size_t i=0; i < z.size(); ++i)
                str << z[i];
            
            round_++;
            return str.str();

        } else if (round_ > 1) 
            return "";

    }

};

#endif
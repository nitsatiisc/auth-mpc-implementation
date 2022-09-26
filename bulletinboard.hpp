#ifndef __AUTH_MPC_BULLETIN_BOARD__
#define __AUTH_MPC_BULLETIN_BOARD__

#include <map>
#include <string>
#include <vector>

typedef std::map<size_t, std::string>  Transcript;

template<typename ChannelT>
class BulletinBoard {

    public:
    BulletinBoard() { channel.init(); round_=0; };

    void publish(const std::string& msg) { channel.publish(msg); };

    std::string get_all_messages() { 
        std::string seed = channel.get_all_messages();
        transcript_[round_] = seed;
        round_++;
        return seed;
     };

    Transcript get_full_transcript() { return transcript_; };

    private:
    ChannelT channel;
    Transcript transcript_;
    size_t round_;

};

// ChannelT = LocalChannel for single prover (trivial)
// ChannelT = BroadcastChannel for distributed prover (network implementation)

class LocalChannel {
    public:
    void init() { };

    void publish(const std::string& msg) 
    {
         current_msg_ = msg;
    };

    std::string get_all_messages() {
        return current_msg_;
    };


    private:
    std::string current_msg_;


};



#endif
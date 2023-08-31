#ifndef __AUTH_MPC_BULLETIN_BOARD__
#define __AUTH_MPC_BULLETIN_BOARD__

#include <map>
#include <string>
#include <vector>
#include <memory>
#include "broadcastclient.hpp"


template<typename ChannelT>
class BulletinBoard {

    public:
    BulletinBoard() { round_=0; bytes_recv_ = 0; bytes_sent_ = 0; };

    void set_channel(const ChannelT& channel)
    {
        this->channel = channel;
    };

    void init() { channel.init(); };

    void publish(const std::string& msg) {
        channel.publish(msg);
        bytes_sent_ += msg.size();
    };

    std::string get_all_messages() { 
        std::string seed = channel.get_all_messages();
        round_++;
        bytes_recv_ += seed.size();
        return seed;
     };

    /*
    std::pair<uint64_t, uint64_t> get_communication_stats() {
        return std::make_pair(channel, bytes_recv_);
    }
    */

    private:
    ChannelT channel;
    size_t round_;
    size_t bytes_sent_;
    size_t bytes_recv_;

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

class BroadcastChannel {
    public:
    BroadcastChannel() {};

    BroadcastChannel(
        const std::string& hub_address,
        size_t client_id
    ) 
    {
        pConnector.reset(new BroadcastClient(hub_address, client_id));
    };

    void init() {
        pConnector->register_with_hub();
    };

    void publish(const std::string& msg)
    {
        std::vector<uint8_t> msg_uint(msg.begin(), msg.end());
        pConnector->send_message_to_hub(msg_uint);
    };

    std::string get_all_messages()
    {
        std::vector<uint8_t> msg_uint = pConnector->recv_message_from_hub();
        std::string msg(msg_uint.begin(), msg_uint.end());
        return msg;
    };

    uint64_t bytes_sent() const {
        return pConnector->bytes_sent();
    };

    uint64_t bytes_received() const {
        return pConnector->bytes_received();
    };

    private:
    std::shared_ptr<BroadcastClient> pConnector;
};



#endif
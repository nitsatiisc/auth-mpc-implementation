#include "broadcasthub.hpp"
#include <cstdlib>

int main(int argc, char *argv[])
{
    std::string hub_address = "localhost:5000";
    uint8_t client_id = atoi(argv[1]);

    BroadcastClient client(hub_address, client_id);
    client.register_with_hub();

    std::vector<uint8_t> msg;
    msg.emplace_back(1);
    client.send_message_to_hub(msg);
    std::vector<uint8_t> recv_msg = client.recv_message_from_hub();

    for(size_t i=0; i < recv_msg.size(); ++i)
    {
        size_t u = (size_t) (recv_msg[i]);
        std::cout << u << std::endl;
    }

    return 0;
}
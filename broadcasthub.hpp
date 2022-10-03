#ifndef __AUTH_MPC_BCAST_HUB__
#define __AUTH_MPC_BCAST_HUB__

#include <bits/stdc++.h>
#include <boost/algorithm/string.hpp>
#include <string>


#include "broadcastclient.hpp"

class BroadcastHub
{
    public:
    BroadcastHub(
        const std::string& hub_address,
        size_t nclients
    ): hub_address(hub_address), nclients(nclients), nmessages(0)
    {
        context = zmq_ctx_new();
        router_socket = zmq_socket(context, ZMQ_ROUTER);
        int mandatory = 1;
        zmq_setsockopt(router_socket, ZMQ_ROUTER_MANDATORY, &mandatory, sizeof(mandatory));
    };


    void broadcast()
    {
        // assemble all messages into a message
        std::string full_message = "";
        for(size_t i=0; i < nclients; ++i)
        {
            full_message = full_message + round_messages[i];
            if (i < nclients - 1)
            {
                full_message = full_message + ":";
            }
        }

        uint8_t proto_code = PROTO_CODE_SEND_MSG_TO_CLIENT;
        for(size_t i=0; i < nclients; ++i)
        {
            std::vector<uint8_t> connection_id = client_id_map[i];
            zmq_send(router_socket, &connection_id[0], connection_id.size(), ZMQ_SNDMORE);
            zmq_send(router_socket, &proto_code, sizeof(proto_code), ZMQ_SNDMORE);
            zmq_send(router_socket, &full_message[0], full_message.size(), 0);
        }

    };


    void process_message(const std::vector<std::vector<uint8_t>>& parts)
    {
        if (parts.size() != 5)
        {
            std::cerr << "Malformed message. Aborting";
            exit(1);
        }

        std::vector<uint8_t> connection_id = parts[0];
        uint8_t client_id = parts[1][0];
        uint8_t code = parts[2][0];
        if (code == PROTO_CODE_DEALER_CONNECT)
        {
            // ack the connection back 
            uint8_t proto_code = PROTO_CODE_HUB_ACK;
            std::string ack_message = "hello";

            zmq_send(router_socket, &connection_id[0], connection_id.size(), ZMQ_SNDMORE);
            zmq_send(router_socket, &proto_code, sizeof(proto_code), ZMQ_SNDMORE);
            zmq_send(router_socket, &ack_message[0], ack_message.size(), 0);
            client_id_map[client_id] = connection_id;

        } else if (code == PROTO_CODE_SEND_MSG_TO_HUB)
        {
            if (round_messages.find(client_id) != round_messages.end())
            {
                std::cerr << "Duplicate client message in a round. Ignoring";
                return;
            }
            round_messages[client_id] = parts[3];
            nmessages++;

            // if we have recieved all client messages, broadcast
            // the combined message to each of them. 
            if (nmessages == nclients) {
                broadcast();
                nmessages = 0;
                round_messages.clear();
            }
            
        }
    };

    

    void start_main_loop()
    {
        // first try to bind the socket to hub_address
        std::string url = "tcp://" + hub_address;
        
        int rc = zmq_bind(router_socket, url.c_str());

        if (rc != 0)
        {
            std::cerr << "Unable to start the hub" << std::endl;
            exit(1);
        }

         zmq_pollitem_t items[1];
        items[0].socket = router_socket;
        items[0].events = ZMQ_POLLIN;

        while(1)
        {
            int rc = zmq_poll(items, 1, -1);

            // incoming data on socket
            if (items[0].revents & ZMQ_POLLIN)
            {
                // we expect id frame, client_id, proto_code, message, hello
                std::vector<std::vector<uint8_t>> parts;
                int more;
                size_t more_size = sizeof(more);
                do {
                    std::vector<uint8_t> part;
                    size_t nb = read_socket(router_socket, part);
                    parts.emplace_back(part);
                    int rc = zmq_getsockopt(router_socket, ZMQ_RCVMORE, &more, &more_size);
                    assert(rc == 0);
                } while(more);

                process_message(parts);
            } 

            
        }

    };

    private:
    void *context;
    void *router_socket;
    size_t nclients;
    size_t nmessages;
    std::map<uint8_t, std::vector<uint8_t>> round_messages;
    std::map<uint8_t, std::vector<uint8_t>> client_id_map;

};

#endif
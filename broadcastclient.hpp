#ifndef __AUTH_MPC_BCAST_CLIENT__
#define __AUTH_MPC_BCAST_CLIENT__

#include <zmq.h>
#include <iostream>
#include <string>

#define PROTO_CODE_DEALER_CONNECT 1
#define HELLO_MESSAGE 2
#define PROTO_CODE_HUB_ACK 3
#define PROTO_CODE_SEND_MSG_TO_HUB 4
#define PROTO_CODE_SEND_MSG_TO_CLIENT 5


typedef std::vector<uint8_t> connection_info_t;
/**
 * Utility functions
 * 
 */
std::string hex_string(const uint8_t *bytes, size_t nb)
{
    std::string str = "";
    char hex_alpha[] = "0123456789ABCDEF";
    for(size_t i=0; i < nb; ++i) {
        uint8_t ch = *(bytes + i);
        str = str + hex_alpha[ch/16] + hex_alpha[ch % 16];
    };
    return str;
}

size_t read_socket(void *socket, std::vector<uint8_t>& data)
{
    zmq_msg_t msg;
    zmq_msg_init(&msg);
    size_t nb = zmq_msg_recv(&msg, socket, 0);
    assert(nb >= 0);
    uint8_t *bytes = (uint8_t *) zmq_msg_data(&msg);
    data.insert(data.end(), bytes, bytes + nb);
    zmq_msg_close(&msg);
    return nb;
}

void read_multipart_message(void *socket, std::vector<std::vector<uint8_t> >& parts)
{
    int more;
    size_t more_size = sizeof(more);
    do
    {
        std::vector<uint8_t> part;
        size_t nb = read_socket(socket, part);
        parts.emplace_back(part);
        int rc = zmq_getsockopt(socket, ZMQ_RCVMORE, &more, &more_size);
        assert(rc == 0);
    } while (more);
}


class BroadcastClient 
{
    public:
    BroadcastClient(
        const std::string& hub_address,
        const uint8_t client_id
    ): hub_address(hub_address), client_id(client_id) 
    {
        context = zmq_ctx_new();
        dealer_socket = zmq_socket(context, ZMQ_DEALER);
        total_bytes_sent = 0;
        total_bytes_recv = 0;
        is_connected = false;
        hello_message = HELLO_MESSAGE;
    };

    bool register_with_hub()
    {
        std::cout << __FUNCTION__ << std::endl;
        std::string url = "tcp://" + hub_address;

        int rc = zmq_connect(dealer_socket, url.c_str());

        if (rc != 0) {
            std::cerr << "Failed to connect to hub via dealer socket" << url << std::endl;
            return false;
        }

        // send three part registration message with empty last frame
        uint8_t code = PROTO_CODE_DEALER_CONNECT;
        zmq_send(dealer_socket, &client_id, sizeof(client_id), ZMQ_SNDMORE);  // id    
        zmq_send(dealer_socket, &code, sizeof(code), ZMQ_SNDMORE);  // proto code
        zmq_send(dealer_socket, 0, 0, ZMQ_SNDMORE);                 // message
        zmq_send(dealer_socket, &hello_message, sizeof(hello_message), 0);
                                                   // local conn id

        std::cout << "Waiting for ACK" << std::endl;
        // block until we hear an acknowledgement back from router
        std::vector<std::vector<uint8_t> > parts;
        read_multipart_message(dealer_socket, parts);

        uint8_t recv_code = parts[0][0];
        std::vector<uint8_t> message = parts[1];

        std::cout << "Received " << message.size() << " bytes from hub:" << hex_string(&message[0], message.size()) << std::endl;

        if (recv_code == PROTO_CODE_HUB_ACK)
        {
            is_connected = true;
        }

        return is_connected;
    };

    void send_message_to_hub(const std::vector<uint8_t>& message)
    {
        assert(is_connected);
        // this is DEALER sending message to hub
        uint8_t code = PROTO_CODE_SEND_MSG_TO_HUB;

        zmq_send(dealer_socket, &client_id, sizeof(client_id), ZMQ_SNDMORE);
        zmq_send(dealer_socket, &code, sizeof(code), ZMQ_SNDMORE);
        zmq_send(dealer_socket, &message[0], message.size(), ZMQ_SNDMORE);
        zmq_send(dealer_socket, &hello_message, sizeof(hello_message), 0); 
        total_bytes_sent += message.size();
    };

    std::vector<uint8_t> recv_message_from_hub()
    {
        assert(is_connected);

        connections[0].socket = dealer_socket;
        connections[0].events = ZMQ_POLLIN;

        long timeout = 1000000;

        while (1)
        {
            zmq_poll(connections, 1, timeout);

            if (connections[0].revents & ZMQ_POLLIN)
            {
                std::vector<std::vector<uint8_t> > parts;
                read_multipart_message(dealer_socket, parts);
                assert(parts.size() == 2);
                return parts[1];
                // return the appropriate part to message.
            }
        }

        return std::vector<uint8_t>();
    };

    private:
    // zmq objects
    void *context;
    void *dealer_socket;
    zmq_pollitem_t connections[1];

    // state info variables
    bool is_connected;
    uint64_t total_bytes_sent;
    uint64_t total_bytes_recv;
    uint8_t client_id;
    std::string hub_address;
    uint8_t hello_message;

};

#endif
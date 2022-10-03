#include "broadcasthub.hpp"
#include <cstdlib>

int main(int argc, char *argv[])
{
    std::string hub_address = "127.0.0.1:8000";
    uint8_t nclients = atoi(argv[1]);

    BroadcastHub hub(hub_address, nclients);
    hub.start_main_loop();
    return 0;
}
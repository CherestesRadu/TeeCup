#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "server.hpp"

int main(int argc, char **argv)
{
    Server server;
    if(!server.open())
    {
        printf("Server Error. Aborting...\n");
    }

    while(server.is_open())
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    printf("Server exitting...\n");
    return 0;
}
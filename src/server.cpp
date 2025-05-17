#include "server.hpp"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>


static void print_socket_error(const char *message)
{
    printf("%s%s\n", message, strerror(errno));
}

Server::~Server()
{
    if(fd != -1)
    {
        close(fd);
        fd = -1;
    }
}

bool Server::open()
{
    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(fd < 0)
    {
        print_socket_error("socket() failed with code: ");
        return false;
    }

    sockaddr_in server_address = {};
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(DEFAULT_PORT);
    server_address.sin_family = AF_INET;    

    if(bind(fd, (const sockaddr *) &server_address, sizeof(sockaddr_in)) < 0)
    {
        print_socket_error("bind() failed with code: ");
        return false;
    }

    if(listen(fd, 10) < 0)
    {
        print_socket_error("listen() failed with code: ");
        return false;
    }

    sockaddr_in client_address = {};
    socklen_t client_addrlen = sizeof(client_address);

    int client_fd = accept(fd, (sockaddr *) &client_address, &client_addrlen);
    if(client_fd < 0)
    {
        print_socket_error("accept() failed with code: ");
        return false;
    }

    char message[] = "Welcome to TeeCup!";
    send(client_fd, message, sizeof(message), 0);

    close(client_fd);
    running = true;

    return true;
}
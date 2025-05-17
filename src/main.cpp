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

constexpr short DEFAULT_PORT = 12345;

void print_socket_error(const char *message)
{
    printf("%s%s\n", message, strerror(errno));
}

int main(int argc, char **argv)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(server_fd < 0)
    {
        print_socket_error("socket() failed with code: ");
        return EXIT_FAILURE;
    }

    sockaddr_in server_address = {};
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(DEFAULT_PORT);
    server_address.sin_family = AF_INET;

    if(bind(server_fd, (const sockaddr *) &server_address, sizeof(sockaddr_in)) < 0)
    {
        print_socket_error("bind() failed with code: ");
        close(server_fd);
        return EXIT_FAILURE;
    }

    if(listen(server_fd, 10) < 0)
    {
        print_socket_error("listen() failed with code: ");
        close(server_fd);
        return EXIT_FAILURE;
    }

    sockaddr_in client_address = {};
    socklen_t client_addrlen = sizeof(client_address);
    int client_fd = accept(server_fd, (sockaddr *) &client_address, &client_addrlen);
    if(client_fd < 0)
    {
        print_socket_error("accept() failed with code: ");
        close(server_fd);
        return EXIT_FAILURE;
    }

    char message[] = "Welcome to TeeCup!";
    send(client_fd, message, sizeof(message), 0);

    close(client_fd);
    close(server_fd);
    return 0;
}
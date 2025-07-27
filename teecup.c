/*




*/

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <pthread.h>

#define SOCKET_ERROR -1
#define SERVER_PORT 8888
#define PRINT_SOCKERROR(err) printf("%s\n", strerror(err))
#define MAX_CLIENTS 8

typedef struct Client
{
    int fd;
    char ip[INET6_ADDRSTRLEN];
} Client;

typedef struct ClientBuffer
{
    Client clients[MAX_CLIENTS];
    int size;

} ClientBuffer;

int add_client(ClientBuffer *buffer, int fd, char *ip)
{
    if (buffer->size >= MAX_CLIENTS)
        return 0;

    Client *new_client = &buffer->clients[buffer->size++];
    new_client->fd = fd;
    memcpy(new_client->ip, ip, INET6_ADDRSTRLEN);
    return 1;
}

void remove_client(ClientBuffer *buffer, char *ip)
{
    for (int i = 0; i < buffer->size; ++i)
    {
        Client *client = &buffer->clients[i];
        if (strcmp(client->ip, ip) == 0)
        {
            // 1 1 x 1

            // 1 x 1 1 1

            // 1 1 1 1 x

            close(client->fd);
            for (int j = i; j < buffer->size - 1; ++j)
                buffer->clients[j] = buffer->clients[j + 1];
            --buffer->size;
            break;
        }
    }
}

void print_clients(ClientBuffer *buffer)
{
    for (int i = 0; i < buffer->size; ++i)
        printf("Socket FD: %d\nSocket IP: %s\n", buffer->clients[i].fd, buffer->clients[i].ip);
}

const char *sockaddr_to_str(const struct sockaddr *addr, char *buf, size_t buflen)
{
    if (addr == NULL || buf == NULL)
        return NULL;

    void *src = NULL;

    switch (addr->sa_family)
    {
    case AF_INET:
    {
        const struct sockaddr_in *a = (const struct sockaddr_in *)addr;
        src = (void *)&a->sin_addr;
        break;
    }
    case AF_INET6:
    {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)addr;
        src = (void *)&a6->sin6_addr;
        break;
    }
    default:
        snprintf(buf, buflen, "<unknown family>");
        return buf;
    }

    if (inet_ntop(addr->sa_family, src, buf, buflen) == NULL)
    {
        snprintf(buf, buflen, "<invalid address>");
    }

    return buf;
}

int set_sock_blockmde(int fd, int blocking)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return 0;
    flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
    return (fcntl(fd, F_SETFL, flags) == 0);
}

int main(int argc, char **argv)
{
    // Initialize server socket
    int server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_fd == SOCKET_ERROR)
    {
        PRINT_SOCKERROR(errno);
        return EXIT_FAILURE;
    }

    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(SERVER_PORT);
    address.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(struct sockaddr_in)) == SOCKET_ERROR)
    {
        PRINT_SOCKERROR(errno);
        return EXIT_FAILURE;
    }

    // Set socket listening mode on SERVER_PORT
    if (listen(server_fd, 10) == SOCKET_ERROR)
    {
        PRINT_SOCKERROR(errno);
        return EXIT_FAILURE;
    }

    set_sock_blockmde(server_fd, 0);
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    // Accept loop

    ClientBuffer clients = {0};

    while (1)
    {
        struct sockaddr_in client_addr = {0};
        socklen_t client_size = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_size);

        if (client_fd != SOCKET_ERROR)
        {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)&client_addr;
            char *s = inet_ntoa(addr_in->sin_addr);
            add_client(&clients, client_fd, s);
            print_clients(&clients);
            remove_client(&clients, s);
            print_clients(&clients);
        }
        else if (errno != EAGAIN)
        {
            PRINT_SOCKERROR(errno);
            break;
        }

        struct timespec ts = {0};
        ts.tv_nsec = 100000000;
        nanosleep(&ts, 0);
    }

    // Disconnect clients

    // Close server
    close(server_fd);

    return 0;
}
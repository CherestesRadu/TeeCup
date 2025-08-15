#ifndef CLIENT_H
#define CLIENT_H

#define MAX_CLIENTS 8

typedef struct Client
{
    int fd;
    char ip[INET6_ADDRSTRLEN];
} Client;

typedef struct ClientBuffer
{
    Client clients[MAX_CLIENTS];
    fd_set master_fds, read_fds;
    int size;

} ClientBuffer;

int add_client(ClientBuffer *buffer, int fd, char *ip);
void remove_client(ClientBuffer *buffer, char *ip);
void print_clients(ClientBuffer *buffer);

#endif // CLIENT_H
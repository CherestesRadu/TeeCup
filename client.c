#include "client.h"

int add_client(ClientBuffer *buffer, int fd, char *ip)
{
    if (buffer->size >= MAX_CLIENTS)
        return 0;

    Client *new_client = &buffer->clients[buffer->size++];
    new_client->fd = fd;
    memcpy(new_client->ip, ip, INET6_ADDRSTRLEN);

    FD_SET(fd, &buffer->master_fds); // Add to master set for select polling
    return 1;
}

void remove_client(ClientBuffer *buffer, char *ip)
{
    for (int i = 0; i < buffer->size; ++i)
    {
        Client *client = &buffer->clients[i];
        if (strcmp(client->ip, ip) == 0)
        {
            FD_CLR(client->fd, &buffer->master_fds); // Eliminate from set
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
        printf("Socket FD: %d\nSocket IP: %s\n\n", buffer->clients[i].fd, buffer->clients[i].ip);
}
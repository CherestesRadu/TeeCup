#include "utils.h"
#include "client.h"

static int server_should_close = 0;

typedef enum Message
{
    JOIN_MESSAGE,
    LEAVE_MESSAGE,
    PING,
    MESSAGE_COUNT
};

typedef enum JoinMessageType
{
    JM_ASK,
    JM_ANSWER,
    JM_COUNT
};

#pragma pack(push, 1)
typedef struct JoinMessage
{
    u16 type;
    u8 name[32];
    u64 timestamp;
} JoinMessage;
#pragma pack(pop)

typedef struct RecvArgs
{
    ClientBuffer *buffer;
    pthread_mutex_t *mutex;
} RecvArgs;

void *recv_thread_func(void *args);

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
    FD_ZERO(&clients.master_fds);

    pthread_t recv_thread;
    RecvArgs recv_args;
    recv_args.buffer = &clients;
    recv_args.mutex = &mutex;

    pthread_create(&recv_thread, 0, recv_thread_func, (RecvArgs *)&recv_args);

    while (1)
    {
        struct sockaddr_in client_addr = {0};
        socklen_t client_size = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_size);

        if (client_fd != SOCKET_ERROR)
        {
            pthread_mutex_lock(&mutex);

            struct sockaddr_in *addr_in = (struct sockaddr_in *)&client_addr;
            char *s = inet_ntoa(addr_in->sin_addr);
            add_client(&clients, client_fd, s);
            print_clients(&clients);

            pthread_mutex_unlock(&mutex);
        }
        else if (errno != EAGAIN)
        {
            PRINT_SOCKERROR(errno);
            break;
        }

        pthread_mutex_lock(&mutex);
        if (server_should_close)
        {
            pthread_mutex_unlock(&mutex);
            break;
        }
        pthread_mutex_unlock(&mutex);

        struct timespec ts = {0};
        ts.tv_nsec = 10000000;
        nanosleep(&ts, 0);
    }

    pthread_join(recv_thread, 0);

    // Disconnect clients
    for (int i = 0; i < clients.size; ++i)
    {
        Client *client = &clients.clients[i];
        close(client->fd);
        client->fd = 0;
        memset(client->ip, 0, INET6_ADDRSTRLEN);
    }
    clients.size = 0;

    // Close server
    close(server_fd);

    return 0;
}

void *recv_thread_func(void *args)
{
    printf("[recv_thread_func] Started!\n");

    RecvArgs *rcm = (RecvArgs *)args;
    ClientBuffer *clients = rcm->buffer;
    pthread_mutex_t *mutex = rcm->mutex;

    while (1)
    {
        pthread_mutex_lock(mutex);

        clients->read_fds = clients->master_fds;
        int max_fd = 0;
        for (int i = 0; i < clients->size; ++i)
        {
            if (clients->clients[i].fd > max_fd)
                max_fd = clients->clients[i].fd;
        }
        pthread_mutex_unlock(mutex);

        struct timeval tv = {0, 10000}; // 100ms
        int activity = select(max_fd + 1, &clients->read_fds, 0, 0, &tv);
        if (activity < 0)
        {
            PRINT_SOCKERROR(errno);
            printf("select() returned %d\n", activity);
            continue;
        }

        pthread_mutex_lock(mutex);
        for (int i = 0; i < clients->size; ++i)
        {
            int fd = clients->clients[i].fd;
            if (FD_ISSET(fd, &clients->read_fds))
            {
                char buffer[1024] = {0};
                ssize_t bytes = recv(fd, buffer, sizeof(buffer) - 1, 0);
                if (bytes <= 0)
                {
                    printf("Client %s disconnected\n", clients->clients[i].ip);
                    remove_client(clients, clients->clients[i].ip);
                    --i;
                }
                else
                {
                    // TODO: Buffering for incomplete packets

                    buffer[bytes] = 0;

                    // Verify bytes for \r\n or \n (only for telnet)
                    for (int i = 0; i < bytes; ++i)
                    {
                        if (buffer[i] == '\r' || buffer[i] == '\n')
                            buffer[i] = 0;
                    }

                    printf("Client %s said: %s (%ld bytes received)\n", clients->clients[i].ip, buffer, bytes);
                    if (strcmp(buffer, "exit") == 0)
                        server_should_close = 1;
                }
            }
        }

        if (server_should_close)
        {
            pthread_mutex_unlock(mutex);
            return 0;
        }

        pthread_mutex_unlock(mutex);
    }

    return 0;
}

u64 htonll(u64 value)
{
    // endianness
    static const int num = 42;
    if (*(const char *)&num == 42) // Little-endian
    {
        u64 hi = htonl((u32)(value >> 32));
        u64 lo = htonl((u32)(value & 0xFFFFFFFF));
        return (lo << 32) | hi;
    }
    else // Big-endian
    {
        return value;
    }
}

u64 ntohll(u64 value)
{
    // Symmetric
    return htonll(value);
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
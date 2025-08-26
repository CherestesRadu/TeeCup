#include "utils.h"
#include "client.h"

static int server_should_close = 0;

typedef enum MessageType
{
    MSG_JOIN = 1,
    MSG_LEAVE,
    MSG_CHAT,
    MSG_PING,
    MSG_COUNT
} MessageType;

typedef struct MessageHeader
{
    u16 length;
    u8 type;
    u8 flags;
} __attribute__((packed)) MessageHeader;

typedef struct JoinMessage
{
    MessageHeader header;
    u8 name[32]; // Client name
} __attribute__((packed)) JoinMessage;

void serialize_join_message(JoinMessage *message, u8 *byte_buffer)
{
    size_t offset = 0;
    u16 net_length = htons(sizeof(JoinMessage));
    memcpy(byte_buffer + offset, &net_length, sizeof(net_length));
    offset += sizeof(net_length);

    byte_buffer[offset++] = MSG_JOIN;
    byte_buffer[offset++] = message->header.flags;

    memcpy(byte_buffer + offset, message->name, strlen(message->name));
    offset + 32;
}

void deserialize_join_message(JoinMessage *message, const u8 *received_buffer)
{
    size_t offset = 0;
    MessageHeader *header = &message->header;
    memcpy(&header->length, received_buffer + offset, sizeof(header->length));
    header->length = ntohs(header->length);
    offset += sizeof(header->length);

    memcpy(&header->type, received_buffer + offset, sizeof(header->type));
    offset += sizeof(header->type);

    memcpy(&header->flags, received_buffer + offset, sizeof(header->flags));
    offset += sizeof(header->flags);

    memcpy(message->name, received_buffer + offset, sizeof(message->name));
    offset += sizeof(message->name);
}

void deserialize_header(MessageHeader *header, u8 *received_buffer)
{
    size_t offset = 0;
    memcpy(&header->length, received_buffer + offset, sizeof(header->length));
    offset += sizeof(header->length);
    header->length = ntohs(header->length);

    memcpy(&header->type, received_buffer + offset, sizeof(header->type));
    offset += sizeof(header->type);

    memcpy(&header->flags, received_buffer + offset, sizeof(header->flags));
    offset += sizeof(header->flags);
}

void deserialize_payload(int type, u8 *payload)
{
    switch (type)
    {
    default:
        return;
    }
}

typedef struct RecvArgs
{
    ClientBuffer *buffer;
    pthread_mutex_t *mutex;
} RecvArgs;

typedef struct CommandArgs
{
    ClientBuffer *buffer;
    pthread_mutex_t *mutex;
} CommandArgs;

void *recv_thread_func(void *args);
void *command_thread_func(void *args);

int main(int argc, char **argv)
{
    // Initialize server socket
    int server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_fd == SOCKET_ERROR)
    {
        PRINT_SOCKERROR(strerror(errno));
        return EXIT_FAILURE;
    }

    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(SERVER_PORT);
    address.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(struct sockaddr_in)) == SOCKET_ERROR)
    {
        PRINT_SOCKERROR(strerror(errno));
        return EXIT_FAILURE;
    }

    // Set socket listening mode on SERVER_PORT
    if (listen(server_fd, 10) == SOCKET_ERROR)
    {
        PRINT_SOCKERROR(strerror(errno));
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

    
    pthread_t command_thread;
    CommandArgs command_args;
    command_args.buffer = &clients;
    command_args.mutex = &mutex;

    pthread_create(&command_thread, 0, command_thread_func, (CommandArgs *)&command_args);
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
            PRINT_SOCKERROR(strerror(errno));
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

ssize_t recv_all_tcp(int fd, u8 *buffer, size_t size)
{
    size_t total_received = 0;
    while (total_received < size)
    {
        ssize_t bytes = recv(fd, buffer + total_received, size - total_received, 0);
        if (bytes == 0)
            return bytes;
        if (bytes < 0)
        {
            PRINT_SOCKERROR(strerror(errno));
            return bytes;
        }

        total_received += bytes;
    }

    return total_received;
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
            PRINT_SOCKERROR(strerror(errno));
            printf("select() returned %d\n", activity);
            continue;
        }

        pthread_mutex_lock(mutex);
        for (int i = 0; i < clients->size; ++i)
        {
            int fd = clients->clients[i].fd;
            if (FD_ISSET(fd, &clients->read_fds))
            {
                MessageHeader header;
                u8 received_header[sizeof(header)] = {0};
                ssize_t bytes_received = recv_all_tcp(fd, received_header, sizeof(header));
                if (bytes_received < 0)
                {
                    // Client disconneted
                    remove_client(clients, clients->clients[i].ip);
                    --i;
                    continue;
                }
                deserialize_header(&header, received_header);

                u16 payload_length = header.length - sizeof(header);
                u8 *payload = malloc(payload_length);
                bytes_received = recv_all_tcp(fd, payload, payload_length);
                if (bytes_received < 0)
                {
                    // Client disconneted
                    remove_client(clients, clients->clients[i].ip);
                    --i;
                    continue;
                }
                deserialize_payload(header.type, payload);

                switch (header.type)
                {
                case MSG_JOIN:
                {
                    JoinMessage message = {0};
                    memcpy(&message.header, &header, sizeof(header));
                    memcpy(&message.name, payload, sizeof(message.name));

                    printf("%s wants to join\n", message.name);

                    // here comes a handshake for extra information
                }
                break;
                }

                free(payload);
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

void *command_thread_func(void *args)
{
    printf("[command_thread_func] Started!\n");
    CommandArgs *command = (CommandArgs *)args;

    while (1)
    {
        char input[128] = {0};
        if (scanf("%127s", input) != 1)
        {
            // Nothing valid, go on
            continue;
        }

        pthread_mutex_lock(command->mutex);
        if (strcmp(input, "exit") == 0)
        {
            server_should_close = 1;
        }
        else if(strcmp(input, "print") == 0) // prints clients
        {
            print_clients(command->buffer);
        }
        else if(strcmp(input, "ping") == 0)
        {
            printf("Pinging...\n");
        }
        else
        {
            printf("Invalid command.\n");
        }

        if (server_should_close == 1)
        {
            pthread_mutex_unlock(command->mutex);
            break;
        }
        pthread_mutex_unlock(command->mutex);
    }
}
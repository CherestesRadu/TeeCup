#include "server.hpp"

static void print_socket_error(const char *message)
{
    printf("%s%s\n", message, strerror(errno));
}

static void set_nonblocking(int fd, bool block)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return; // handle error appropriately

    if (block)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    else
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

Server::~Server()
{
    if (fd != -1)
    {
        close(fd);
        fd = -1;
    }
}

bool Server::open()
{
    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0)
    {
        print_socket_error("socket() failed with code: ");
        return false;
    }

    sockaddr_in server_address = {};
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(DEFAULT_PORT);
    server_address.sin_family = AF_INET;

    if (bind(fd, (const sockaddr *)&server_address, sizeof(sockaddr_in)) < 0)
    {
        print_socket_error("bind() failed with code: ");
        return false;
    }

    if (listen(fd, 10) < 0)
    {
        print_socket_error("listen() failed with code: ");
        return false;
    }
    running = true;
    set_nonblocking(fd, true);
    std::thread handle_connections(
        [](Server &server)
        {
            while (server.running)
            {
                sockaddr_in client_address = {};
                socklen_t client_addrlen = sizeof(client_address);
                Client client;
                {
                    std::lock_guard<std::mutex> guard(server.mtx);
                    client.fd = accept(server.fd, (sockaddr *)&client_address, &client_addrlen);
                }

                if (client.fd < 0)
                {
                    print_socket_error("accept() failed with code: ");
                    continue;
                }

                std::string message = "Welcome to the server!";
                ssize_t bytes_sent = send(client.fd, message.data(), message.size(), 0);

                if (bytes_sent < message.size() || bytes_sent == -1)
                    print_socket_error("send() failed with error: ");

                {
                    std::lock_guard<std::mutex> guard(server.mtx);
                    server.clients.push_back(client);
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        },
        std::ref(*this));

    handle_connections.detach();
    return true;
}
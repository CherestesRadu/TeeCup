#ifndef TEECUP_SERVER_H
#define TEECUP_SERVER_H

#define DEFAULT_PORT 12345

#include <atomic>
#include <mutex>
#include <thread>
#include <string>
#include <vector>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

struct Client
{
    int fd;
    std::string ip;
};

class Server
{
public:
    Server() = default;
    ~Server();

    inline bool is_open() const { return running; }
    bool open();
private:
    std::atomic<bool> running = false;
    std::mutex mtx;
    std::vector<Client> clients;
    int fd = -1;
};

#endif
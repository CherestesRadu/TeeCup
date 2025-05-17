#ifndef TEECUP_SERVER_H
#define TEECUP_SERVER_H

#define DEFAULT_PORT 12345

class Server
{
public:
    Server() = default;
    ~Server();

    bool open();
private:
    bool running = false;
    int fd = -1;
};

#endif
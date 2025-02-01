#include <iostream>
#include <vector>
#include <cstring>
#include <thread>
#include <mutex>

#define DEFAULT_PORT 12345

#include "socket.h"

int main()
{
	Socket server;
	server.Open(SOCK_STREAM);
	server.Bind(DEFAULT_PORT);
	server.Listen();

	Socket client = server.Accept();
	if (client.fd != -1)
	{
		std::cout << "Client connected\n";
		server.Send(client, "Hello, client!", 14);
		Sleep(10000);
	}

    return 0;
}
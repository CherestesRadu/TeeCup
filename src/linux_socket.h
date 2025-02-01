#ifndef LINUX_SOCKET_HH
#define LINUX_SOCKET_HH

// Linux headers
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

struct Socket
{
	int fd = -1; // File descriptor
	
	void Open(int type)
	{
		if(type == SOCK_STREAM)
			fd = socket(AF_INET, SOCK_STREAM, 0);
		else if(type == SOCK_DGRAM)
			fd = socket(AF_INET, SOCK_DGRAM, 0);

		if(fd == -1)
		{
			std::cerr << "Error: socket creation failed\n";
			exit(1);
		}
	}

	void Close()
	{
		if(fd != -1)
			close(fd);
		fd = -1;
	}

	void Bind(int port)
	{
		struct sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = INADDR_ANY;

		if(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1)
		{
			std::cerr << "Error: bind failed\n";
			exit(1);
		}
	}

	void Listen(int backlog = 5)
	{
		if(listen(fd, backlog) == -1)
		{
			std::cerr << "Error: listen failed\n";
			exit(1);
		}
	}

	Socket Accept()
	{
		Socket client;
		client.fd = accept(fd, NULL, NULL);
		if(client.fd == -1)
		{
			std::cerr << "Error: accept failed\n";
			exit(1);
		}
		return client;
	}

	void Connect(const char* ip, int port)
	{
		struct sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = inet_addr(ip);

		if(connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1)
		{
			std::cerr << "Error: connect failed\n";
			exit(1);
		}
	}

	void Send(Socket &client, const char* data, int size)
	{
		if(send(client.fd, data, size, 0) == -1)
		{
			std::cerr << "Error: send failed\n";
			exit(1);
		}
	}

	int Receive(char* buffer, int size)
	{
		int bytes = recv(fd, buffer, size, 0);
		if(bytes == -1)
		{
			std::cerr << "Error: recv failed\n";
			exit(1);
		}
		return bytes;
	}
};

#endif
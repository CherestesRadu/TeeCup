#ifndef SOCKET_HH
#define SOCKET_HH

#ifdef _WIN32
#include "win32_socket.h"
#else
#include "linux_socket.h"
#endif

#endif
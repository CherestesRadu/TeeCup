#ifndef UTILS_H
#define UTILS_H

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <stdarg.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/select.h>
#include <assert.h>

#define SOCKET_ERROR -1
#define SERVER_PORT 8888

void PRINT_SOCKERROR(const char *err);

u64 htonll(u64 value);
u64 ntohll(u64 value);
const char *sockaddr_to_str(const struct sockaddr *addr, char *buf, size_t buflen);
int set_sock_blockmde(int fd, int blocking);

// Prints all socket errors to errors.log
void PRINT_SOCKERROR(const char *message);
#endif // UTILS_H
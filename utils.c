#include "utils.h"

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

void PRINT_SOCKERROR(const char *message)
{
    time_t now = time(0);
    struct tm *t = localtime(&now);
    char timebuff[32] = {0};
    strftime(timebuff, sizeof(timebuff), "%Y-%m-%d %H:%M:%S", t);

    FILE *logfile = fopen("errors.log", "a");
    fprintf(logfile, "%s:%s\n", timebuff, message);
    fflush(logfile);
    fclose(logfile);
}
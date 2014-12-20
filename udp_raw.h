#ifndef UDP_RAW
#define UDP_RAW

#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <sys/types.h>

#define BUF_SIZE (65536)

struct pseudohdr
{
    u_int32_t source;
    u_int32_t destination;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t length;
};

int send_udp_raw (int sock, u_int32_t ip_saddr, u_int32_t ip_daddr, u_int32_t source_port, u_int32_t dest_port, char *data, u_int32_t length);
int pars_udp_raw (char *package, int size_package, u_int32_t prog_port);

#endif
#ifndef CLIENT_H
#define CLIENT_H

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/udp.h>
#include <netinet/ip.h>

#define LOCAL_ADDRESS ("192.168.0.2")
#define SERVER_ADDRESS ("192.168.0.1")
#define SERVER_PORT (3022)
#define CLIENT_PORT (3022)

/*struct udphdr
{
	u_int16_t source;
	u_int16_t dest;
	u_int16_t len;
	u_int16_t check;
};*/

#endif
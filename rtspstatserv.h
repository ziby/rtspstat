#ifndef SERVER_H
#define SERVER_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CLIENT (4)
#define DEF_PACK_BUF (65536)
#define DEF_FILE_BUF (8192)

#define LOCAL_ADDRESS ("192.168.0.2")
#define SERVER_ADDRESS ("192.168.0.1")
#define SERVER_PORT (3022)
#define CLIENT_PORT (3022)

void usage();

#endif
#include "udp_raw.h"
#include "client.h"
#include "chksum.h"
#include "parse_pcap.h"

#define SOCKET (3)
#define DEF_PACK_BUF (65536)

int main (int argc, char **argv)
{		

	int sock = -1; // сокет для приема клиентов
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	// AF_INET - использование TCP/IP (IPv4)
	// SOCK_RAW - указывает на использование сырых сокетов

	if (sock < 0) {
		perror("[\033[31m*\033[0m] Error! Can't create socket");
		exit(EXIT_FAILURE);
	}
	else {
		printf("[\033[32m*\033[0m] Socket ok\n");
	}

	char data[22];
	strcpy (data, "[\033[32m*\033[0m]  Запрос от клиента");
	
    if (send_udp_raw (SOCKET, inet_addr(LOCAL_ADDRESS), inet_addr(SERVER_ADDRESS), CLIENT_PORT, SERVER_PORT, data, 6) < 0 ) {
    	perror("[\033[31m*\033[0m] Error! Package not recieve\n");
    	exit(EXIT_FAILURE);
    }

    int wait_socket = -1; // сокет для приема клиентов
	wait_socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	// AF_INET - использование TCP/IP (IPv4)
	// SOCK_RAW - указывает на использование сырых сокетов
	// IPPROTO_UDP - использование протокола транспортного уровня UDP

	if (wait_socket < 0) {
		perror("[\033[31m*\033[0m] Error! Can't create socket");
		exit(EXIT_FAILURE);
	}
	else {
		printf("[\033[32m*\033[0m] Socket ok\n");
	}

	char readSockBuf[DEF_PACK_BUF];
    
    while (1)
    {
	    int sizePackage = recv(wait_socket, readSockBuf, sizeof(readSockBuf), 0);

		if (sizePackage < 0) {
			perror("[\033[31m*\033[0m] Error! Recieve package\n");
			exit(EXIT_FAILURE);
		}

		struct iphdr *ip = (struct iphdr *)readSockBuf;
		int i = ip->ihl * 4;

		if (ip->protocol != IPPROTO_UDP || i + sizeof(struct udphdr) >= sizePackage) continue;
		struct udphdr *udp = (struct udphdr*) (readSockBuf + ip->ihl * 4); // UDP заголовок
		if (ntohs(udp->dest) != CLIENT_PORT) continue;
			
		i += sizeof(struct udphdr);

		struct stat *this_stat = (struct stat *) (readSockBuf + i);

		printf("Processed %d packets and %u MBytes, in %d files\n", this_stat->pkts_count, this_stat->pkts_length, argc-1);
	  	printf("Min Speed: %f, Max Speed: %f, Average Speed: %f\n", this_stat->min_speed, this_stat->max_speed, this_stat->aver_speed);

	  	break;
	}
    exit(EXIT_SUCCESS);
}
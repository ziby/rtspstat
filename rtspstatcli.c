#include "udp_raw.h"
#include "rtspstatcli.h"
#include "chksum.h"
#include "parse_pcap.h"

#define DEF_PACK_BUF (65536)

int main (int argc, char **argv)
{		

	if (argc < 2) {
		perror("[\033[31m*\033[0m]Error! Wrong Arguments\n");
		exit(EXIT_FAILURE);
	}

	int sock = -1; // сокет для приема клиентов
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	// AF_INET - использование TCP/IP (IPv4)
	// SOCK_RAW - указывает на использование сырых сокетов

	if (sock < 0) {
		perror("[\033[31m*\033[0m] Error! Can't create socket");
		exit(EXIT_FAILURE);
	}
	else {
		printf("[\033[32m*\033[0m] Socket for send ok\n");
	}

	char data[APP_PACK_SIZE]; // память для содержимого пакета
	u_int32_t *req_ip_addr = (u_int32_t *)(data);
	*req_ip_addr = inet_addr(argv[1]);
	
    if (send_udp_raw (sock, inet_addr(LOCAL_ADDRESS), inet_addr(SERVER_ADDRESS), CLIENT_PORT, SERVER_PORT, data, sizeof(u_int32_t)) < 0 ) {
    	perror("[\033[31m*\033[0m] Error! Package not recieve\n");
    	exit(EXIT_FAILURE);
    }
    else {
    	printf("[\033[32m*\033[0m] Send ok\n");
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
		printf("[\033[32m*\033[0m] Socket for recv ok\n");
	}

	char read_sock_buf[sizeof(struct stat)];

    if (recv_udp_raw(wait_socket, 1, inet_addr(SERVER_ADDRESS), CLIENT_PORT, read_sock_buf, sizeof(struct stat)) == 0) {
		perror("[\033[31m*\033[0m] Error! Recieve package\n");
		exit(EXIT_FAILURE);
	}
	else {
		printf("[\033[32m*\033[0m] Recv ok\n");
	}

	struct stat *this_stat = (struct stat *) (read_sock_buf);

	printf("Processed %d packets and %u MBytes, in %d files\n", this_stat->pkts_count, this_stat->pkts_length, argc-1);
	printf("Min Speed: %f, Max Speed: %f, Average Speed: %f\n", this_stat->min_speed, this_stat->max_speed, this_stat->aver_speed);

    exit(EXIT_SUCCESS);
}
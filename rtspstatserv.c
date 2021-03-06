#include "rtspstatserv.h"
#include "parse_pcap.h"
#include "udp_raw.h"

void usage()
{
	printf("rtspstat - клиент-серверное приложение для получения статистики работы протокола rtsp\nrtspstatserv - серверная часть\nrtspstatserv [-f pathfile]\nfile формата .pcap программы wireshark\n");
}

int main (int argc, char **argv)
{
	if (argc != 2) {
		perror("[\033[31m*\033[0m]Error! Wrong Arguments\n");
		// \033[31m - окрашивает в красный вывод
		// \033[0m - окрашивает вывод в цвет по умолчанию
		usage();
		exit(EXIT_FAILURE);
	}
	else {
		printf("[\033[32m*\033[0m] Arguments ok\n");
		// \033[32m - окрашивает в зеленый вывод
		// \033[0m - окрашивает вывод в цвет по умолчанию
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
		printf("[\033[32m*\033[0m] Recv socket ok\n");
	}

	int sock = -1; // сокет для приема клиентов
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	// AF_INET - использование TCP/IP (IPv4)
	// SOCK_RAW - указывает на использование сырых сокетов

	if (socket < 0) {
		perror("[\033[31m*\033[0m] Error! Can't create socket");
		exit(EXIT_FAILURE);
	}
	else {
		printf("[\033[32m*\033[0m] Send socket ok\n");
	}
	char read_sock_buf[DEF_PACK_BUF];
	while(1)
	{
		u_int32_t ip_cliaddr = recv_udp_raw(wait_socket, 0, 0, SERVER_PORT, read_sock_buf, DEF_PACK_BUF);
		if (ip_cliaddr == 0) {
			perror("[\033[31m*\033[0m] Error! Recieve package\n");
			exit(EXIT_FAILURE);
		}
		else {
			printf("[\033[32m*\033[0m] Client ok\n");
		}

		u_int32_t *ip_req = (u_int32_t *) read_sock_buf;
	
		char data[sizeof(struct stat)];
		struct stat *this_stat = (struct stat *) data;

		if (parse_pcap(this_stat, argc, argv, *ip_req) == -1)
			exit (EXIT_FAILURE);

		if (sock < 0) {
			perror("[\033[31m*\033[0m] Error! Can't create socket");
			exit(EXIT_FAILURE);
		}
		else {
			printf("[\033[32m*\033[0m] Send socket ok\n");
		}

		if (send_udp_raw (sock, inet_addr(SERVER_ADDRESS), ip_cliaddr, CLIENT_PORT, SERVER_PORT, data, sizeof(struct stat)) < 0 ) {
    		perror("[\033[31m*\033[0m] Error! Package not recieve\n");
    		exit(EXIT_FAILURE);
    	}
		
		printf("Processed %d packets and %u MBytes, in %d files\n", this_stat->pkts_count, this_stat->pkts_length, argc-1);
  		printf("Min Speed: %f, Max Speed: %f, Average Speed: %f\n", this_stat->min_speed, this_stat->max_speed, this_stat->aver_speed);

		printf("\n");
	}
	exit(EXIT_SUCCESS);
}
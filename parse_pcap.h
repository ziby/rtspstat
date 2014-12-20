#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define ETHER_TYPE_IP (0x0800)
#define INF (1000000000.0)

struct stat
{
  unsigned int pkts_count;   // количество пакетов
  unsigned long pkts_length; // размер всех пакетов
  double max_speed; // максимальная скорость
  double min_speed; // минимальная скорость
  double aver_speed; // средняя скорость
};

int parse_pcap(struct stat *this_stat, int argc, char **argv, u_int32_t ip_daddr);
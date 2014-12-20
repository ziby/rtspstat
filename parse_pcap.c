#include "parse_pcap.h"

//------------------------------------------------------------------- 
int parse_pcap(struct stat *this_stat, int argc, char **argv, u_int32_t ip_daddr)
//int main(int argc, char **argv) 
{
  if (argc < 2) return -1;

  this_stat->pkts_count = 0;   // количество пакетов
  this_stat->pkts_length = 0; // размер всех пакетов
  this_stat->max_speed = 0; // максимальная скорость
  this_stat->min_speed = INF; // минимальная скорость
  this_stat->aver_speed = 0; // средняя скорость
  
  unsigned long current_ts = 0; // текущая секунда для подсчета пакетов в секунду
  unsigned long cur_pkts_length = 0;  // размер всех пакетов за секунду

  struct pcap_pkthdr header;
  const u_char *cur_packet; // текущий пакет
  
  //  fprintf(stderr, "Usage: %s [input pcaps]\n", argv[0]); 
   
  int fnum = 1; // номер pcap файла
  for (fnum = 1; fnum < argc; fnum++) {  // цикл по всем файлам
 
    pcap_t *handle_pcap; // дескриптор pcap файла
    char errbuf[PCAP_ERRBUF_SIZE]; // буфер для ошибок при открытии pcap файла
    handle_pcap = pcap_open_offline(argv[fnum], errbuf);  // открыть pcap файл
 
    if (handle_pcap == NULL) { 
      return -1;
    } 
 
    while (cur_packet = pcap_next(handle_pcap,&header)) { // читаем следующий пакет
      u_char *pkt_ptr = (u_char *)cur_packet;
      
      // int ether_type = ((int)(pkt_ptr[12]) << 8) | (int)pkt_ptr[13]; 
      // 13 и 14 октет ethernet frame это ether_type
      int ether_type = ntohs((u_int16_t)(pkt_ptr[12]));
      int ether_offset = 0; 
 
      if (ether_type == ETHER_TYPE_IP)
        ether_offset = 14; // смещение данных пакеты относительно начала
      else 
         fprintf(stderr, "Unknown ethernet type, %04X, skipping...\n", ether_type); 
 
      pkt_ptr += ether_offset;  //пропускаем Ethernet II header 
      struct ip *ip_hdr = (struct ip *)pkt_ptr; // указатель на структуру ip пакета 
      if (ip_hdr->ip_dst.s_addr != ip_daddr) continue;
 
      int packet_length = ntohs(ip_hdr->ip_len); // длина всего ip пакета
 
      if (current_ts == 0) {
         current_ts = header.ts.tv_sec; // зададим время начала
      } else if (header.ts.tv_sec > current_ts) { // если наступила следующая секунда
         double cur_speed = cur_pkts_length / 1000.0; // текущая скорость Kbps
         if (cur_speed > this_stat->max_speed) this_stat->max_speed = cur_speed;
         if (cur_speed < this_stat->min_speed) this_stat->min_speed = cur_speed;
         cur_pkts_length = 0; // длина пакетов за эту секунду
         current_ts = header.ts.tv_sec; 
      } 
 
      cur_pkts_length += packet_length;
      this_stat->pkts_length += packet_length; 
      this_stat->pkts_count++;
    }
    pcap_close(handle_pcap);  // закрываем текущий файл
  }

  this_stat->aver_speed = (double)this_stat->pkts_length / (double)this_stat->pkts_count / 1000.0; // средняя скорость
  this_stat->pkts_length /= 1e6;  // размер пакетов В Мб
 
  //printf("Processed %d packets and %u MBytes, in %d files\n", this_stat->pkts_count, this_stat->pkts_length, argc-1);
  //printf("Min Speed: %f, Max Speed: %f, Average Speed: %f", this_stat->min_speed, this_stat->max_speed, this_stat->aver_speed);
  return 0;
}
#include "udp_raw.h"

#include <stdio.h>

int send_udp_raw (int sock, u_int32_t ip_saddr, u_int32_t ip_daddr, u_int32_t source_port, u_int32_t dest_port, char *data, u_int32_t length)
    {
        char buffer[BUF_SIZE]; // создаем буфер для хранения датаграммы перед отправкой
        memset (buffer, 0, sizeof(buffer)); // зануляем его

        struct iphdr *ip = (struct iphdr*) buffer; // структура для хранения IP заголовка пакета
        struct udphdr *udp = (struct udphdr*) (buffer + sizeof(struct iphdr)); // UDP заголовок

        /* IP заголовок */
    	    ip->frag_off = 0;
    	    ip->version = 4;
    	    ip->ihl = 5;
    	    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr));
    	    ip->id = 0;
    	    ip->ttl = 40;
    	    ip->protocol = IPPROTO_UDP;
    	    ip->saddr = ip_saddr;
    	    ip->daddr = ip_daddr;
    	    ip->check = chksum((unsigned short *)buffer, ip->ihl);
        /***************/

        /* UDP заголовок */
            udp->source = htons(source_port); //Порт отправителя
            udp->dest = htons(dest_port); //Порт получателя
            udp->len = sizeof(struct udphdr); //Длина UDP пакета
            udp->check = 0; //Контрольная сумма
        /***************/

        char *tempdata = buffer + sizeof(struct iphdr) + sizeof(struct udphdr); // расположение данных
        memcpy (tempdata, data, length);
        udp->len += htons(length);
        ip->tot_len += htons(length);

        struct pseudohdr pshdr; // псевдозаголовок, необходим для расчета контрольной суммы по RFC 1071
        /* Псевдозаголовок */
    	    pshdr.destination = ip_daddr;
    	    pshdr.source = ip_saddr;
    	    pshdr.placeholder = 0;
    	    pshdr.protocol = ip->protocol;
    	    pshdr.length = udp->len;
        /***************/
        
        char *psddatagr = malloc(sizeof(struct pseudohdr) + length);
         // область памяти, по которой будет считать контрольная сумма
        udp->check = chksum ((unsigned short*) psddatagr, sizeof(struct pseudohdr) + length);
        free(psddatagr);

    	struct sockaddr_in to; // местоназначение пакета
    	to.sin_addr.s_addr = ip->daddr;
    	to.sin_family = AF_INET;
        to.sin_port = udp->dest;

        return sendto(sock, buffer, ntohs(ip->tot_len), 0, (struct sockaddr*)&to, sizeof(to));
    }
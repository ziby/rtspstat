TARGETCLI = rtspstatcli.out
TARGETSERV = rtspstatserv.out
SRCSERV = chksum.c parse_pcap.c udp_raw.c rtspstatserv.c
SRCCLI = chksum.c parse_pcap.c udp_raw.c rtspstatcli.c
OBJSSERV = $(SRCSERV:.c=.o)
OBJSCLI = $(SRCCLI:.c=.o)
CC = gcc
CFLAGS = -c -Wall
LFLAGSCLI = -lpcap
LFLAGSSERV = -lpcap

all: $(TARGETCLI) $(TARGETSERV)
$(TARGETSERV): $(OBJSSERV)
	$(CC) $(LFLAGSSERV) $(OBJSSERV) -o $(TARGETSERV)

$(TARGETCLI): $(OBJSCLI)
	$(CC) $(LFLAGSCLI) $(OBJSCLI) -o $(TARGETCLI)

.c.o:
	$(CC) $(CFLAGS) $< -o $@
	# .c.o - шаблон для указания как .c получить .o
	# $< $@ - переменные для этого шаблона. Первый указывает на .c файл, второй - на .o

clean:
	rm -rf *.o $(TARGETCLI) $(TARGETSERV)

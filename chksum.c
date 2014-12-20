unsigned short chksum(unsigned short *addr, int len) {
// расчет контрольной суммы по алгоритму, описанному в RFC 1071
    long sum = 0;

    while (len > 1) {
        sum += *(addr++);
        len -= 2;
    }

    if (len > 0)
        sum += *addr;

    while (sum >> 16)
        sum = ((sum & 0xffff) + (sum >> 16));

    sum = ~sum;

    return ((unsigned short) sum);
}
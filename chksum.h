#ifdef CHKSUM
#define CHKSUM

#include <stdlib.h>

// псевдозаголовок, необходимый для расчета контрольной суммы UDP - пакет

unsigned short chksum(unsigned short *addr, int len);

#endif
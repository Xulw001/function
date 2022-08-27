#include "bloomfilter.h"
#include "../algorithm/hash.h"
#include <malloc.h>
#include <stdarg.h>

int createBloomFilter(struct bloomfilter **ppbmfilter, int size, int func,
                      ...) {
  struct bloomfilter *pbmfilter =
      (struct bloomfilter *)malloc(sizeof(struct bloomfilter));
  if (pbmfilter == 0x00) {
    return -1;
  }

  pbmfilter->size = size ? size : 1024;
  pbmfilter->bits = (byte *)malloc(sizeof(byte) * pbmfilter->size);
  if (func == 0) {
    pbmfilter->nfun = 8;
    pbmfilter->pfun = (hash *)malloc(sizeof(hash) * 8);
    pbmfilter->pfun[0] = BKDRHash;
    pbmfilter->pfun[1] = DJBHash;
    pbmfilter->pfun[2] = JSHash;
    pbmfilter->pfun[3] = RSHash;
    pbmfilter->pfun[4] = SDBMHash;
    pbmfilter->pfun[5] = MurmurHash;
    pbmfilter->pfun[6] = DEKHash;
    pbmfilter->pfun[7] = APHash;
  } else {
    va_list va;
    va_start(va, func);
    pbmfilter->nfun = func;
    pbmfilter->pfun = (hash *)malloc(sizeof(hash) * func);
    for (int i = 0; i < func; i++) {
      pbmfilter->pfun[i] = va_arg(va, hash);
    }
    va_end(va);
  }

  *ppbmfilter = pbmfilter;
  return 0;
}

int destoryBloomFilter(struct bloomfilter **ppbmfilter) {
  if (*ppbmfilter == 0x00) {
    return 0;
  }

  if ((*ppbmfilter)->pfun != 0x00) {
    free((*ppbmfilter)->pfun);
    (*ppbmfilter)->pfun = 0x00;
  }

  if ((*ppbmfilter)->bits != 0x00) {
    free((*ppbmfilter)->bits);
    (*ppbmfilter)->bits = 0x00;
  }

  free(*ppbmfilter);
  *ppbmfilter = 0x00;

  return 0;
}

#define IS_SET(arr, val) ((arr[(val) >> 5] >> ((val)&0x000001F)) & 0x00000001)
#define BIT_SET(arr, val) \
  arr[(val) >> 5] = ((arr[(val) >> 5]) | 1 << ((val)&0x000001F))

int chkBloomFilter(struct bloomfilter *pbmfilter, const char *ptr, int len) {
  for (int i = 0; i < pbmfilter->nfun; i++) {
    if (!IS_SET(pbmfilter->bits,
                (pbmfilter->pfun[i](ptr, len) % pbmfilter->size))) {
      return 0;
    }
  }
  return 1;
}

int addBloomFilter(struct bloomfilter *pbmfilter, const char *ptr, int len) {
  for (int i = 0; i < pbmfilter->nfun; i++) {
    BIT_SET(pbmfilter->bits, pbmfilter->pfun[i](ptr, len) % pbmfilter->size);
  }
  return 1;
}

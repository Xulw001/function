#include "bloomfilter.h"

#include <fcntl.h>
#include <malloc.h>
#include <math.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "../algorithm/hash.h"

#ifdef BIG
#define SIGN 0x424D46494C544552U
#else
#define SIGN 0x5245544C49464D42U
#endif

int calBloomFilterBytes(int size, double errRate, int *funs) {
  int bitarrs = 0;
  bitarrs = ceil(-1.00 * size * log(errRate) / 0.480453);
  bitarrs = (bitarrs + 31) / 32 * 32;  // align for int
  *funs = floor(0.693147 * bitarrs / size);
  return bitarrs / BYTE_BITS;
}

int loadBloomFilter(struct bloomfilter *pbmfilter) {
  int ret;
  int fd;
  struct bloomfilterHeader bfheader;
  if (pbmfilter->source == NULL) {
    return -1;
  }
  fd = open(pbmfilter->source, O_RDONLY);
  if (fd == -1) {
    return -1;
  }
  ret = read(fd, &bfheader, sizeof(struct bloomfilterHeader));
  if (ret != sizeof(struct bloomfilterHeader)) {
    return -1;
  }

  if (bfheader.sign != SIGN) {
    return -1;
  }

  pbmfilter->elems = bfheader.elems;
  pbmfilter->count = bfheader.count;
  pbmfilter->nfun = bfheader.nfun;
  pbmfilter->bytes = bfheader.bytes;
  pbmfilter->rate = bfheader.rate;
  pbmfilter->pbits = (uint *)malloc(sizeof(byte) * pbmfilter->bytes);
  if (pbmfilter->pbits == 0x00) {
    return -1;
  }

  ret = read(fd, pbmfilter->pbits, pbmfilter->bytes);
  if (ret != pbmfilter->bytes) {
    return -1;
  }

  close(fd);

  return 0;
}

int createBloomFilter(struct bloomfilter **ppbmfilter, int argvs, ...) {
  if (argvs < 1 || argvs > 5) {
    return -1;
  }

  struct bloomfilter *pbmfilter =
      (struct bloomfilter *)malloc(sizeof(struct bloomfilter));
  if (pbmfilter == 0x00) {
    return -1;
  }
  memset(pbmfilter, 0x00, sizeof(struct bloomfilter));

  va_list va;
  va_start(va, argvs);

  switch (argvs) {
    case NEWDEFAULTEX:  // use default parameters to init and file to save
                        // result
      pbmfilter->source = va_arg(va, const char *);
    case NEWDEFAULT:  // use default parameters to init without file
      pbmfilter->elems = DEFAULT_MAX_SiZE;
      pbmfilter->rate = DEFAULT_ERR_RATE;
      break;
    case NEW:  // use user-specified parameters to init without file
      pbmfilter->elems = va_arg(va, int);
      pbmfilter->rate = va_arg(va, double);
      break;
    case NEWEX:  // use user-specified parameters to init and file to save
                 // result
      pbmfilter->elems = va_arg(va, int);
      pbmfilter->rate = va_arg(va, double);
      pbmfilter->source = va_arg(va, const char *);
      break;
    case EXIST:  // use user-specified file to init and save
      pbmfilter->source = va_arg(va, const char *);
      break;
  }
  va_end(va);

  if (pbmfilter->elems == 0 && pbmfilter->rate == 0.0) {
    if (loadBloomFilter(pbmfilter) != 0) {
      goto ERR;
    }
  } else {
    pbmfilter->bytes = calBloomFilterBytes(pbmfilter->elems, pbmfilter->rate,
                                           &pbmfilter->nfun);
    pbmfilter->pbits = (uint *)malloc(sizeof(byte) * pbmfilter->bytes);
    if (pbmfilter->pbits == 0x00) {
      goto ERR;
    }
  }

  switch (pbmfilter->nfun % 10) {
    case 9:
      pbmfilter->pfun[9] = ELFHash;
    case 8:
      pbmfilter->pfun[8] = PJWHash;
    case 7:
      pbmfilter->pfun[7] = APHash;
    case 6:
      pbmfilter->pfun[6] = DEKHash;
    case 5:
      pbmfilter->pfun[5] = SDBMHash;
    case 4:
      pbmfilter->pfun[4] = RSHash;
    case 3:
      pbmfilter->pfun[3] = JSHash;
    case 2:
      pbmfilter->pfun[2] = DJBHash;
    case 1:
      pbmfilter->pfun[1] = BKDRHash;
    case 0:
      pbmfilter->pfun[0] = MurmurHash;
      break;
  }

  *ppbmfilter = pbmfilter;
  return 0;

ERR:
  if (pbmfilter != 0x00) {
    if (pbmfilter->pbits != 0x00) {
      free(pbmfilter->pbits);
    }
    free(pbmfilter);
  }
  return -1;
}

int destoryBloomFilter(struct bloomfilter **ppbmfilter) {
  int ret = 0;
  if (*ppbmfilter == 0x00) {
    return 0;
  }

  if ((*ppbmfilter)->source != 0x00) {
    ret = saveBloomFilter(*ppbmfilter, (*ppbmfilter)->source);
  }

  if ((*ppbmfilter)->pbits != 0x00) {
    free((*ppbmfilter)->pbits);
    (*ppbmfilter)->pbits = 0x00;
  }

  free(*ppbmfilter);
  *ppbmfilter = 0x00;

  return ret;
}

#define IS_SET(arr, val) ((arr[(val) >> 5] >> ((val)&0x000001F)) & 0x00000001)
#define BIT_SET(arr, val) \
  arr[(val) >> 5] = ((arr[(val) >> 5]) | 1 << ((val)&0x000001F))

int chkBloomFilter(struct bloomfilter *pbmfilter, const char *ptr, int len) {
  if (pbmfilter == 0x00 || ptr == 0x00 || len <= 0) {
    return 0;
  }

  for (int i = 0; i < pbmfilter->nfun; i++) {
    int idx = (i - 10) & 0x7;
    if (!IS_SET(pbmfilter->pbits,
                (pbmfilter->pfun[idx](ptr, len, 0) % pbmfilter->elems))) {
      return 0;
    }
  }
  return 1;
}

int addBloomFilter(struct bloomfilter *pbmfilter, const char *ptr, int len) {
  if (pbmfilter == 0x00 || ptr == 0x00 || len <= 0) {
    return 0;
  }

  for (int i = 0; i < pbmfilter->nfun; i++) {
    int idx = (i - 10) & 0x7;
    BIT_SET(pbmfilter->pbits,
            pbmfilter->pfun[idx](ptr, len, 0) % pbmfilter->elems);
  }

  pbmfilter->count++;
  return 1;
}

int saveBloomFilter(struct bloomfilter *pbmfilter, const char *source) {
  int ret;
  int fd;
  struct bloomfilterHeader bfheader;
  if (source == NULL) {
    return -1;
  }

  bfheader.sign = SIGN;
  bfheader.bytes = pbmfilter->bytes;
  bfheader.count = pbmfilter->count;
  bfheader.elems = pbmfilter->elems;
  bfheader.nfun = pbmfilter->nfun;
  bfheader.rate = pbmfilter->rate;

  fd = open(pbmfilter->source, O_WRONLY);
  if (fd == -1) {
    return -1;
  }

  ret = write(fd, &bfheader, sizeof(struct bloomfilterHeader));
  if (ret != sizeof(struct bloomfilterHeader)) {
    return -1;
  }

  ret = write(fd, pbmfilter->pbits, pbmfilter->bytes);
  if (ret != pbmfilter->bytes) {
    return -1;
  }

  close(fd);

  return 0;
}
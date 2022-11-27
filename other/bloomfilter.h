#pragma once
#include "../base/common_type.h"

typedef uint (*hash)(const char *, int, int);

#define DEFAULT_MAX_SiZE 10000000
#define DEFAULT_ERR_RATE 0.00001
#define BYTE_BITS 8

enum {
  EXIST = 2,
  NEWDEFAULT,
  NEWDEFAULTEX,
  NEW,
  NEWEX,
};
#pragma pack(1)
struct bloomfilter {
  uint elems;  // element' size
  uint count;
  uint nfun;  // hash function' size
  uint bytes;
  const char *source;
  double rate;
  uint *pbits;  //
  hash pfun[0xA];
};

struct bloomfilterHeader {
  uint64_t sign;
  uint elems;  // element' size
  uint count;
  uint nfun;  // hash function' size
  uint bytes;
  double rate;
};
#pragma pack()

#ifdef __cplusplus
extern "C" {
#endif
int createBloomFilter(struct bloomfilter **ppbmfilter, int argvs, ...);
int destoryBloomFilter(struct bloomfilter **ppbmfilter);
int chkBloomFilter(struct bloomfilter *pbmfilter, const char *ptr, int len);
int addBloomFilter(struct bloomfilter *pbmfilter, const char *ptr, int len);
int saveBloomFilter(struct bloomfilter *pbmfilter, const char *source);
#ifdef __cplusplus
}
#endif

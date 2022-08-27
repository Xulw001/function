#pragma once

typedef int (*hash)(const char *, int);

struct bloomfilter {
  uint size;
  uint nfun;
  uint *bits;
  hash *pfun;
};

#ifdef __cplusplus
extern "C" {
#endif
int createBloomFilter(struct bloomfilter **ppbmfilter, int size, int func, ...);
int destoryBloomFilter(struct bloomfilter **ppbmfilter);
int chkBloomFilter(struct bloomfilter *pbmfilter, const char *ptr, int len);
int addBloomFilter(struct bloomfilter *pbmfilter, const char *ptr, int len);
#ifdef __cplusplus
}
#endif

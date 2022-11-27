#pragma once
#include "../base/common_type.h"
#ifdef __cplusplus
extern "C" {
#endif
// BKDRHash，APHash，DJBHash，JSHash，RSHash，SDBMHash，PJWHash，ELFHash，DEK，FNV1
uint MurmurHash(const char *key, int len, int seed);
uint BKDRHash(const char *key, int len, int seed);
uint DJBHash(const char *key, int len, int seed);
uint JSHash(const char *key, int len, int seed);
uint RSHash(const char *key, int len, int seed);
uint SDBMHash(const char *key, int len, int seed);
uint DEKHash(const char *key, int len, int seed);
uint APHash(const char *key, int len, int seed);
uint PJWHash(const char *key, int len, int seed);
uint ELFHash(const char *key, int len, int seed);
#ifdef __cplusplus
}
#endif
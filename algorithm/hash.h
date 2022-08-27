#pragma once
#include "../base/common_type.h"
#ifdef __cplusplus
extern "C" {
#endif
// BKDRHash，APHash，DJBHash，JSHash，RSHash，SDBMHash，PJWHash，ELFHash，DEK，FNV1
uint BKDRHash(const char *key, int len);
uint DJBHash(const char *key, int len);
uint JSHash(const char *key, int len);
uint RSHash(const char *key, int len);
uint SDBMHash(const char *key, int len);
uint PJWHash(const char *key, int len);
uint ELFHash(const char *key, int len);
uint DEKHash(const char *key, int len);
uint APHash(const char *key, int len);
uint MurmurHash(const char *key, int len);
#ifdef __cplusplus
}
#endif
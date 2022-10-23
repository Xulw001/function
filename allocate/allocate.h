#pragma once
#include "../base/functional.h"
#include "../thread/lock.h"

#ifdef __cplusplus
extern "C" {
#endif
int createHeapManage();
int destoryHeapManage();
void *_allocate(unsigned int ulAreaSize);
void _release(void *ptr, int size);
void _thread_release();

#define allocate(size) _allocate(size)
#define release(ptr) _release(ptr, 0)

#ifdef __cplusplus
}
#endif

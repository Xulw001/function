#pragma once
#include "..\base\functional.h"
#include "..\thread\lock.h"

struct Heapinf {
  unsigned int unMem_flg;
  unsigned int unMem_size;
};

struct HeapBlock {
  struct list_head list;
  int tid;
};

#define PAGEBLOCK (1024 * 128)
#define PAGESIZE (1024 * 64)
#define MINIPAGE 1024

#define ALLOCATE_ALL_BLOCK 0xFFFFFFFF    // for big block
#define ALLOCATE_SEP_BLOCK 0xEEEEEEEE    // for small block
#define ALLOCATE_STATUS_USED 0x22222222  // used flag
#define ALLOCATE_STATUS_FREE 0x11111111  // unused flag

struct HeapInstance {
  struct list_head head;
};

#define length_align(len) \
  ((len + sizeof(void *) - 1) / sizeof(void *) * sizeof(void *))

#ifdef __cplusplus
extern "C" {
#endif
void createHeapManage();
void destoryHeapManage();
void *_allocate(unsigned int ulAreaSize, unsigned int tid);
void _release(void *ptr);


#ifndef _MulThread
#define allocate(size) _allocate(size, 0);
#else
#define allocate(size, tid) _allocate(size, tid);
#endif
#define release(ptr) _release(ptr);

#ifdef __cplusplus
}
#endif

#include "lock.h"
#ifdef _WIN32
#include <windows.h>
#endif

void lock(unsigned int* lock_t) {
#ifdef _WIN32
  while (_InterlockedCompareExchange((unsigned long*)lock_t, LOCK, FREE) == LOCK)
    //返回lock_t初始值
    ;
#else
  while (__sync_bool_compare_and_swap(lock_t, FREE, LOCK) ==
         0)  //写入新值成功返回1，写入失败返回0
    ;
#endif
}

void unlock(unsigned int* lock_t) { *lock_t = FREE; }

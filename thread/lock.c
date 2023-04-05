#include "lock.h"
#ifdef _WIN32
#include <windows.h>
#endif

void lock(unsigned int* lock_t) {
#ifdef _WIN32
  // return Destination's value
  while (_InterlockedCompareExchange((unsigned long*)lock_t, LOCK, FREE) ==
         LOCK)
#else
  // return 1 while success, othersize return 0
  while (__sync_bool_compare_and_swap(lock_t, FREE, LOCK) == 0)
#endif
    ;
}

void unlock(unsigned int* lock_t) {
#ifndef _WIN32
  __sync_lock_test_and_set(lock_t, FREE);
#else
  _InterlockedExchange((unsigned long*)lock_t, FREE);
#endif
}

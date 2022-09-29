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
  // return 1 while success£¬othersize return 0
  while (__sync_bool_compare_and_swap(lock_t, FREE, LOCK) == 0)
#endif
    ;
}

int islock(unsigned int* lock_t) {
#ifdef _WIN32
  if (_InterlockedCompareExchange((unsigned long*)lock_t, FREE, FREE) == LOCK)
#else
  if (__sync_bool_compare_and_swap(lock_t, FREE, FREE) == 0)
#endif
    return 1;
  return 0;
}

void unlock(unsigned int* lock_t) { *lock_t = FREE; }

#include "lock.h"
#ifdef _WIN32
#include <windows.h>
#endif

void lock(unsigned int* lock_t) {
#ifdef _WIN32
  while (_InterlockedCompareExchange((unsigned long*)lock_t, LOCK, FREE) == LOCK)
    //����lock_t��ʼֵ
    ;
#else
  while (__sync_bool_compare_and_swap(lock_t, FREE, LOCK) ==
         0)  //д����ֵ�ɹ�����1��д��ʧ�ܷ���0
    ;
#endif
}

void unlock(unsigned int* lock_t) { *lock_t = FREE; }

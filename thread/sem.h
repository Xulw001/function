#pragma once
#ifndef _WIN32
#include <sys/ipc.h>
#include <sys/sem.h>
#else
#include <windows.h>
#endif

#ifndef _WIN32
union semun {
  int val;               // cmd == SETVAL
  struct semid_ds *buf;  // cmd == IPC_SET cmd == IPC_STAT
  ushort *array;         // cmd == SETALL cmd = GETALL
};
#define HANDLE int
#endif

#ifdef __cplusplus
extern "C" {
#endif
int sem_open(HANDLE *sem_id, int val, int max);
int sem_del(HANDLE sem_id);
int sem_p(HANDLE sem_id);
int sem_v(HANDLE sem_id, int val);
#ifdef __cplusplus
}
#endif

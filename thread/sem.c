#include "sem.h"

int sem_open(HANDLE* sem_id, int val, int max) {
#ifndef _WIN32
  union semun sem_union;
  *sem_id = semget(IPC_PRIVATE, 1, 0666);
  if (*sem_id == 0) {
    return 1;
  }

  sem_union.val = val;
  if (semctl(*sem_id, 0, SETVAL, sem_union) == -1) {
    return 1;
  }
#else
  *sem_id = CreateSemaphore(0, val, max, NULL);
  if (*sem_id == 0) {
    return 1;
  }
#endif
  return 0;
}

int sem_del(HANDLE sem_id) {
#ifndef _WIN32
  union semun sem_union;
  if (semctl(sem_id, 0, IPC_RMID, sem_union) == -1) {
#else
  if (CloseHandle(sem_id) == 0) {
#endif
    return 1;
  }
  return 0;
}

int sem_p(HANDLE sem_id) {
#ifndef _WIN32
  struct sembuf sem_buf;
  sem_buf.sem_num = 0;         //
  sem_buf.sem_op = -1;         // P
  sem_buf.sem_flg = SEM_UNDO;  //
  if (semop(sem_id, &sem_buf, 1) == -1) {
#else
  if (WaitForSingleObject(sem_id, INFINITE) == -1) {
#endif
    return 1;
  }
  return 0;
}

int sem_v(HANDLE sem_id, int val) {
#ifndef _WIN32
  struct sembuf sem_buf;
  sem_buf.sem_num = 0;
  sem_buf.sem_op = val;  // V
  sem_buf.sem_flg = SEM_UNDO;
  if (semop(sem_id, &sem_buf, 1) == -1) {
#else
  while (ReleaseSemaphore(sem_id, val, NULL) == 0) {
    if (GetLastError() != 0x12A)
#endif
    return 1;
  }

  return 0;
}

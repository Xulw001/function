#include "sem.h"

int sem_open(int *sem_id) {
  *sem_id = semget(IPC_PRIVATE, 1, 0666);
  if (*sem_id == 0) {
    return 1;
  }
  return 0;
}

int sem_set(int sem_id, int val) {
  union semun sem_union;
  sem_union.val = val;
  if (semctl(sem_id, 0, SETVAL, sem_union) == -1) {
    return 1;
  }
  return 0;
}

int sem_del(int sem_id) {
  union semun sem_union;
  if (semctl(sem_id, 0, IPC_RMID, sem_union) == -1) {
    return 1;
  }
  return 0;
}

int sem_p(int sem_id) {
  struct sembuf sem_buf;
  sem_buf.sem_num = 0;         //
  sem_buf.sem_op = -1;         // P
  sem_buf.sem_flg = SEM_UNDO;  //
  if (semop(sem_id, &sem_buf, 1) == -1) {
    return 1;
  }
  return 0;
}

int sem_v(int sem_id) {
  struct sembuf sem_buf;
  sem_buf.sem_num = 0;
  sem_buf.sem_op = 1;  // V
  sem_buf.sem_flg = SEM_UNDO;
  if (semop(sem_id, &sem_buf, 1) == -1) {
    return 1;
  }
  return 0;
}

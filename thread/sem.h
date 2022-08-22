#ifdef _WIN32
#include <sys/ipc.h>
#include <sys/sem.h>
#else
#include <synchapi.h>
#endif

union semun {
  int val;               // cmd == SETVAL
  struct semid_ds *buf;  // cmd == IPC_SET���� cmd == IPC_STAT
  ushort *array;         // cmd == SETALL���� cmd = GETALL
};
#ifdef __cplusplus
extern "C" {
#endif
int sem_init(int* sem_id);
int sem_del(int sem_id);
int sem_p(int sem_id);
int sem_v(int sem_id)
int sem_set(int sem_id, int val);
#ifdef __cplusplus
}
#endif
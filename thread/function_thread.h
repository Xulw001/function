#pragma once

#include <pthread.h>

#include "sem.h"

struct task {
  void* (*execute)(void*);
  void* args;
  int keepalive;
  struct task* next;
};

struct thread_pool {
  unsigned int shutdown;     // �����̳߳��Ƿ���ֹ
  unsigned int max_threads;  // �̳߳��������
  unsigned int t_free;       // �����߳���(�ǳ־�/����)
  unsigned int onfull;  // �߳������޴���  0: ֱ�ӷ��� 1���ȴ��ն���
  unsigned int lock_task;    // ���������
  pthread_t* threads;        // �߳���Ϣ
  struct task *tasks, *end;  // ������Ϣ
  HANDLE task_ready;         // ���������
  HANDLE task_empty;         // �������δ��
};

#ifdef __cplusplus
extern "C" {
#endif
int createPool(struct thread_pool** pool, int max_thread, int onfull);
int destroyPool(struct thread_pool* pool);
int addTaskPool(struct thread_pool* pool, void* (*execute)(void*), void* args,
                int keep_alive);
#ifdef __cplusplus
}
#endif
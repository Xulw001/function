#pragma once
#ifndef _USE_CAS
#ifndef _WIN32
#include <pthread.h>
#else
#include <windows.h>
#endif

#ifndef _WIN32
#define thrd_t pthread_t
#define mtx_t pthread_mutex_t
#define cond_t pthread_cond_t
#else
#define thrd_t uintptr_t
#define mtx_t SRWLOCK
#define cond_t CONDITION_VARIABLE
#endif

struct task {
  void* (*execute)(int*, void*);
  void* args;
  int keepalive;
  struct task* next;
};

struct thread_pool {
  unsigned int shutdown;     // �����̳߳��Ƿ���ֹ
  unsigned int max_threads;  // �̳߳��������
  unsigned int t_free;       // �����߳���(�ǳ־�/����)
  unsigned int onfull;  // �߳������޴���  0: ֱ�ӷ��� 1���ȴ��ն���
  struct task *tasks, *end;  // ������Ϣ
  thrd_t* threads;           // �߳���Ϣ
  mtx_t lock_ready;
  mtx_t lock_empty;
  cond_t task_ready;  // ���������
  cond_t task_empty;  // �������δ��
};

#ifdef __cplusplus
extern "C" {
#endif
int createPool(struct thread_pool** pool, int max_thread, int onfull);
int destroyPool(struct thread_pool* pool);
int addTaskPool(struct thread_pool* pool, void* (*execute)(int*, void*),
                void* args, int keep_alive);
#ifdef __cplusplus
}
#endif
#endif

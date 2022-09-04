#pragma once
#ifndef _WIN32
#include <pthread.h>
#else
#include <process.h>
#include <windows.h>
#endif
#include "sem.h"

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
  void* (*execute)(int*,
                   void*);  // first args must be type int*,execute function
                            // should use first args kill the running thread
  void* args;
  int keepalive;
  struct task* next;
};

struct thread_pool {
  unsigned int shutdown;     // sign pool shutdown
  unsigned int max_threads;  // max thread num
  unsigned int t_free;       // free thread num
  unsigned int onfull;  // add task when pool is full  0: return 1: wait empty
  struct task *tasks, *end;  // task queue
  thrd_t* threads;           // thread handle
#ifndef _USE_CAS
  mtx_t lock_ready;
  mtx_t lock_empty;
  cond_t task_ready;  //
  cond_t task_empty;  //
#else
  unsigned int lock_task;  // lock for task queue
  HANDLE task_ready;       // sign task ready
  HANDLE task_empty;       // sign task empty
#endif
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

#pragma once
#ifdef _USE_CAS
#ifndef _WIN32
#include <pthread.h>
#else
#include <windows.h>
#endif
#include "sem.h"

#ifndef _WIN32
#define thrd_t pthread_t
#else
#define thrd_t uintptr_t
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
  unsigned int onfull;  // add task when pool is full  0: return 1£ºwait empty
  struct task *tasks, *end;  // task queue
  thrd_t* threads;           // thread handle
  unsigned int lock_task;    // lock for task queue
  HANDLE task_ready;         // sign task ready
  HANDLE task_empty;         // sign task empty
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
#endif _USE_CAS

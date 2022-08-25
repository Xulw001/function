#pragma once
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
  void* (*execute)(void*);
  void* args;
  int keepalive;
  struct task* next;
};

struct thread_pool {
  unsigned int shutdown;     // 监听线程池是否终止
  unsigned int max_threads;  // 线程池最大容量
  unsigned int t_free;       // 空闲线程数(非持久/空闲)
  unsigned int onfull;  // 线程数上限处理  0: 直接返回 1：等待空队列
  struct task *tasks, *end;  // 任务信息
  thrd_t* threads;           // 线程信息
  unsigned int lock_task;	// 任务队列锁
  HANDLE task_ready;  // 任务待处理
  HANDLE task_empty;  // 任务队列未满
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

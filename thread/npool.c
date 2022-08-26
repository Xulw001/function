#include "npool.h"
#include "lock.h"

#include <malloc.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#else
#include <process.h>
#endif
#ifdef _DEBUG
#include <stdio.h>
#endif

#ifndef _WIN32
static void* execute(void* argvs) {
#else
static u_int __stdcall execute(void* argvs) {
#endif
  int keepalive = 0;
  struct task* task = 0;
  struct thread_pool* pool = (struct thread_pool*)argvs;
  while (!keepalive) {
    sem_p(pool->task_ready);
#ifndef _WIN32
    if (__sync_bool_compare_and_swap(&pool->shutdown, 0, 0) == 0)
#else
    if (_InterlockedCompareExchange((unsigned long*)&pool->shutdown, 0, 0) == 1)
#endif
    {
#ifdef _DEBUG
      printf("shutdown success\n");
#endif
      goto Error;
    }
#ifdef _DEBUG
    printf("sub success\n");
#endif

    lock(&pool->lock_task);
    task = pool->tasks;
    pool->tasks = task->next;
    if (pool->tasks == 0x00) {
      pool->end = 0x00;
    }
    unlock(&pool->lock_task);

    task->execute(&pool->shutdown, task->args);

    if (task->keepalive) {
#ifndef _WIN32
      __sync_fetch_and_add(&pool->t_free, 1);
#else
      _InterlockedIncrement((unsigned long*)&pool->t_free);
#endif
      sem_v(pool->task_empty, 1);
    }

    free(task);
  }
Error:
#ifndef _WIN32
  pthread_exit(NULL);
#else
  _endthreadex(0);
#endif
  return 0;
}

int createPool(struct thread_pool** pool, int max_thread, int onfull) {
  *pool = (struct thread_pool*)malloc(sizeof(struct thread_pool));
  if (NULL == *pool) {
    return -1;
  }

  if (max_thread == 0) {
#ifndef _WIN32
    max_thread = (sysconf(_SC_NPROCESSORS_ONLN) - 1) * 2;
#else
    ;
#endif
  }

  (*pool)->onfull = onfull;
  (*pool)->max_threads = max_thread;
  (*pool)->t_free = max_thread;
  (*pool)->shutdown = 0;
  (*pool)->lock_task = FREE;
  (*pool)->tasks = (*pool)->end = 0;
  (*pool)->threads = (thrd_t*)malloc(sizeof(thrd_t) * max_thread);
  if (NULL == (*pool)->threads) {
    return -1;
  }

  if (sem_open(&((*pool)->task_ready), 0, max_thread) != 0) {
    return -2;
  }

  if (sem_open(&((*pool)->task_empty), max_thread, max_thread) != 0) {
    return -2;
  }

  for (int i = 0; i < max_thread; i++) {
#ifndef _WIN32
    if (pthread_create(&(*pool)->threads[i], NULL, execute, (void*)*pool) != 0)
#else
    if (((*pool)->threads[i] =
            _beginthreadex(NULL, 0, execute, (void*)*pool, 0, 0)) == 0)
#endif
    {
      destroyPool(*pool);
      return -3;
    }
  }

  return 0;
}

int destroyPool(struct thread_pool* pool) {
  struct task* end_task = NULL;

  if (pool == 0 || pool->shutdown) {
    return 0;
  }
#ifndef _WIN32
  __sync_lock_test_and_set(&pool->shutdown, 1);
#else
  InterlockedExchange((unsigned long*)&pool->shutdown, 1);
#endif

  if (sem_v(pool->task_ready, pool->max_threads) != 0) {
#ifdef _WIN32
    if (GetLastError() != 0x12A)  // Too many posts were made to a semaphore.
#endif
      return -2;
  }

  for (int i = 0; i < pool->max_threads; i++) {
    if (pool->threads[i] != 0) {
#ifndef _WIN32
      if (pthread_join(pool->threads[i], NULL) != 0)
#else
      if (WaitForSingleObject(pool->threads[i], INFINITE) != 0)
#endif
      {
        return -4;
      }
    }
  }

#ifdef _DEBUG
  int count = 0;
#endif
  while (pool->tasks) {
    end_task = pool->tasks;
    pool->tasks = end_task->next;
    free(end_task);
#ifdef _DEBUG
    count++;
#endif
  }
#ifdef _DEBUG
  printf("killed = %d\n", count);
#endif

  sem_del(pool->task_empty);
  sem_del(pool->task_ready);

  free(pool->threads);

  free(pool);

  return 0;
}

int addTaskPool(struct thread_pool* pool, void* (*execute)(int*, void*),
                void* args, int keep_alive) {
  struct task* work_task = NULL;

  if (execute == NULL) {
    return 0;
  }

  if (pool->shutdown) {
    return 2;
  }

#ifndef _WIN32
  while (__sync_bool_compare_and_swap(&pool->t_free, 0, 0) == 1)
#else
  while (_InterlockedCompareExchange((unsigned long*)&pool->t_free, 0, 0) == 0)
#endif
  {
    if (pool->onfull == 0) {
      return 1;
    }
    sem_p(pool->task_empty);
  }

  work_task = (struct task*)malloc(sizeof(struct task));
  if (NULL == work_task) {
    return -1;
  }

  work_task->execute = execute;
  work_task->args = args;
  work_task->keepalive = keep_alive;
  work_task->next = NULL;

  lock(&pool->lock_task);
  if (NULL == pool->end) {
    pool->tasks = pool->end = work_task;
  } else {
    pool->end->next = work_task;
    pool->end = work_task;
  }
#ifdef _DEBUG
  printf("add success\n");
#endif

  if (sem_v(pool->task_ready, 1) != 0) {
    unlock(&pool->lock_task);
    return -4;
  }

  unlock(&pool->lock_task);

  if (keep_alive) {
#ifndef _WIN32
    __sync_fetch_and_sub(&pool->t_free, 1);
#else
    _InterlockedDecrement((unsigned long*)&pool->t_free);
#endif
    sem_p(pool->task_empty);
  }

  return 0;
}

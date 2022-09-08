#include "pool.h"
#ifndef _USE_CAS
#include <malloc.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
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
#ifndef _WIN32
    pthread_mutex_lock(&pool->lock_ready);
#else
    AcquireSRWLockExclusive(&pool->lock_ready);
#endif
    while (pool->tasks == 0 && pool->shutdown == 0) {
#ifndef _WIN32
      pthread_cond_wait(&pool->task_ready, &pool->lock_ready);
#else
      SleepConditionVariableSRW(&pool->task_ready, &pool->lock_ready, INFINITE,
                                0);
#endif
    }

    if (pool->shutdown) {
#ifndef _WIN32
      pthread_mutex_unlock(&pool->lock_ready);
#else
      ReleaseSRWLockExclusive(&pool->lock_ready);
#endif
      goto Error;
    }
#ifdef _DEBUG
    printf("sub success\n");
#endif
    task = pool->tasks;
    pool->tasks = task->next;
    if (pool->tasks == 0x00) {
      pool->end = 0x00;
    }
#ifndef _WIN32
    pthread_mutex_unlock(&pool->lock_ready);
#else
    ReleaseSRWLockExclusive(&pool->lock_ready);
#endif

    task->execute(&pool->shutdown, task->args);

    if (task->keepalive) {
#ifndef _WIN32
      pthread_mutex_lock(&pool->lock_empty);
      pool->t_free++;
      pthread_mutex_unlock(&pool->lock_empty);
      pthread_cond_signal(&pool->task_empty);
#else
      AcquireSRWLockExclusive(&pool->lock_empty);
      pool->t_free++;
      ReleaseSRWLockExclusive(&pool->lock_empty);
      WakeConditionVariable(&pool->task_empty);
#endif
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
    max_thread = (sysconf(_SC_NPROCESSORS_ONLN) - 1);
#else
    SYSTEM_INFO si;
    memset(&si, 0, sizeof(SYSTEM_INFO));
    GetSystemInfo(&si);
    max_thread = si.dwNumberOfProcessors - 1;
#endif
  }

  (*pool)->onfull = onfull;
  (*pool)->max_threads = max_thread;
  (*pool)->t_free = max_thread;
  (*pool)->shutdown = 0;
  (*pool)->tasks = (*pool)->end = 0;
  (*pool)->threads = (thrd_t*)malloc(sizeof(thrd_t) * max_thread);
  if (NULL == (*pool)->threads) {
    return -1;
  }

#ifndef _WIN32
  pthread_mutex_init(&((*pool)->lock_ready), 0);
  pthread_mutex_init(&((*pool)->lock_empty), 0);
  pthread_cond_init(&((*pool)->task_ready), 0);
  pthread_cond_init(&((*pool)->task_empty), 0);
#else
  InitializeSRWLock(&((*pool)->lock_ready));
  InitializeSRWLock(&((*pool)->lock_empty));
  InitializeConditionVariable(&((*pool)->task_ready));
  InitializeConditionVariable(&((*pool)->task_empty));
#endif

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

  if (pool->shutdown) {
    return 0;
  }
#ifndef _WIN32
  pthread_mutex_lock(&pool->lock_ready);
#else
  AcquireSRWLockExclusive(&pool->lock_ready);
#endif
  pool->shutdown = 1;
#ifndef _WIN32
  pthread_mutex_unlock(&pool->lock_ready);
  pthread_cond_broadcast(&pool->task_ready);
#else
  ReleaseSRWLockExclusive(&pool->lock_ready);
  WakeAllConditionVariable(&pool->task_ready);
#endif

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

#ifndef _WIN32
  pthread_cond_destroy(&pool->task_empty);
  pthread_cond_destroy(&pool->task_empty);
  pthread_mutex_destroy(&pool->lock_ready);
  pthread_mutex_destroy(&pool->lock_empty);
#endif

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
  pthread_mutex_lock(&pool->lock_empty);
#else
  AcquireSRWLockExclusive(&pool->lock_empty);
#endif

  while (pool->t_free == 0) {
    if (pool->onfull == 0) {
#ifndef _WIN32
      pthread_mutex_unlock(&pool->lock_empty);
#else
      ReleaseSRWLockExclusive(&pool->lock_empty);
#endif
      return 1;
    }

#ifndef _WIN32
    pthread_cond_wait(&pool->task_empty, &pool->lock_empty);
#else
    SleepConditionVariableSRW(&pool->task_empty, &pool->lock_empty, INFINITE,
                              0);
#endif
  }

#ifndef _WIN32
  pthread_mutex_unlock(&pool->lock_empty);
#else
  ReleaseSRWLockExclusive(&pool->lock_empty);
#endif

  work_task = (struct task*)malloc(sizeof(struct task));
  if (NULL == work_task) {
    return -1;
  }

  work_task->execute = execute;
  work_task->args = args;
  work_task->keepalive = keep_alive;
  work_task->next = NULL;

#ifndef _WIN32
  pthread_mutex_lock(&pool->lock_ready);
#else
  AcquireSRWLockExclusive(&pool->lock_ready);
#endif
  if (NULL == pool->end) {
    pool->tasks = pool->end = work_task;
  } else {
    pool->end->next = work_task;
    pool->end = work_task;
  }
#ifdef _DEBUG
  printf("add success\n");
#endif
#ifndef _WIN32
  pthread_mutex_unlock(&pool->lock_ready);
  pthread_cond_signal(&pool->task_ready);
#else
  ReleaseSRWLockExclusive(&pool->lock_ready);
  WakeConditionVariable(&pool->task_ready);
#endif

  if (keep_alive) {
#ifndef _WIN32
    pthread_mutex_lock(&pool->lock_empty);
#else
    AcquireSRWLockExclusive(&pool->lock_ready);
#endif
    pool->t_free--;
#ifndef _WIN32
    pthread_mutex_unlock(&pool->lock_empty);
#else
    ReleaseSRWLockExclusive(&pool->lock_ready);
#endif
  }

  return 0;
}
#endif

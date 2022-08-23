#include "function_thread.h"

#include <malloc.h>
#include <string.h>
#include <unistd.h>

#include "lock.h"

static void* execute(void* argvs) {
  int keepalive = 0;
  struct task* task = 0;
  struct thread_pool* pool = (struct thread_pool*)argvs;
  while (!keepalive) {
    sem_p(pool->task_ready);

    if (pool->shutdown) {
      goto Error;
    }

    lock(&pool->lock_task);
    task = pool->tasks;
    pool->tasks = task->next;
    if (pool->tasks == 0x00) {
      pool->end = 0x00;
    }
    unlock(&pool->lock_task);

    task->execute(task->args);

    if (task->keepalive) {
#ifndef _WIN32
      __sync_fetch_and_add(&pool->t_free, 1);
#else
      _InterlockedIncrement(&pool->t_free);
#endif
      sem_v(pool->task_empty, 1);
    }
    free(task);
  }
Error:
  pthread_exit(NULL);
  return 0;
}

int create_pool(struct thread_pool** pool, int max_thread, int onfull) {
  *pool = (struct thread_pool*)malloc(sizeof(struct thread_pool));
  if (NULL == *pool) {
    return -1;
  }

  if (max_thread == 0) {
#ifdef _WIN32
    ;
#else
    max_thread = sysconf(_SC_NPROCESSORS_ONLN) - 1;
#endif
  }

  (*pool)->onfull = onfull;
  (*pool)->max_threads = max_thread;
  (*pool)->t_free = max_thread;
  (*pool)->shutdown = 0;
  (*pool)->lock_task = FREE;
  (*pool)->tasks = (*pool)->end = 0;
  (*pool)->threads = (pthread_t*)malloc(sizeof(pthread_t) * max_thread);
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
    if (pthread_create(&(*pool)->threads[i], NULL, execute, (void*)*pool) !=
        0) {
      destroy_pool(*pool);
      return -3;
    }
  }

  return 0;
}

int destroy_pool(struct thread_pool* pool) {
  struct task* end_task = NULL;

  if (pool->shutdown) {
    return 0;
  }

  pool->shutdown = 1;

  if (sem_v(pool->task_ready, pool->max_threads) != 0) {
#ifdef _WIN32
    if (GetLastError() != 0x12A)  // Too many posts were made to a semaphore.
#endif
      return -2;
  }

  for (int i = 0; i < pool->max_threads; i++) {
    if (pool->threads[i] != 0) {
      if (pthread_join(pool->threads[i], NULL) != 0) {
        return -4;
      }
    }
  }

  while (pool->tasks) {
    end_task = pool->tasks;
    pool->tasks = end_task->next;
    free(end_task);
  }

  sem_del(pool->task_empty);
  sem_del(pool->task_ready);

  free(pool->threads);

  free(pool);

  return 0;
}

int addtask_pool(struct thread_pool* pool, void* (*execute)(void*), void* args,
                 int keep_alive) {
  int ret;
  struct task* work_task = NULL;

  if (execute == NULL) {
    return 0;
  }

  if (!pool->onfull) {
#ifndef _WIN32
    if (__sync_fetch_add_add(&pool->t_free, 0))
#else
    InterlockedAnd(&pool->t_free, 1);
    if (pool->t_free)
#endif
      return 1;
  }

  sem_p(pool->task_empty);
  if (pool->shutdown) {
    return 2;
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

  if (sem_v(pool->task_ready, 1) != 0) {
    unlock(&pool->lock_task);
    return -4;
  }

  unlock(&pool->lock_task);

  if (keep_alive) {
#ifndef _WIN32
    __sync_fetch_and_sub(&pool->t_free, 1);
#else
    _InterlockedDecrement(&pool->t_free);
#endif
    sem_p(pool->task_empty);
  }

  return 0;
}
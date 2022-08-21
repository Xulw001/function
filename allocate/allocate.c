#include "allocate.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

#include <malloc.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
HANDLE mp_mutex = NULL;
#else
pthread_mutex_t mp_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
static struct HeapInstance *_instance;

BOOL lock() {
#ifdef _MulThread
#ifdef _WIN32
  return (0 == WaitForSingleObject(mp_mutex, INFINITE));
#else
  return (0 == pthread_mutex_lock(&mp_mutex));
#endif
#endif
}

BOOL unlock() {
#ifdef _MulThread
#ifdef _WIN32
  if (ReleaseMutex(mp_mutex)) {
    return TRUE;
  } else {
    return FALSE;
  }
#else
  return (0 == pthread_mutex_unlock(&mp_mutex));
#endif
#endif
}

#define list_add_tail_safe(ptr, list) \
  ({                                  \
    lock();                           \
    list_add_tail(ptr, list);         \
    unlock();                         \
  })

static void *_allocate_block(int mode, unsigned int unMemSize) {
#ifdef _WIN32
  HGLOBAL hGlobal = 0;
#endif
  void *pReturn_code = NULL;
  struct HeapBlock *pHeap = NULL;
  struct Heapinf *pHeapInf = NULL;
  unsigned int unActMemsize = 0;
  int fd = -1;

  switch (mode) {
    case 0:
      unActMemsize = unMemSize;
      break;
    default:
      unActMemsize = PAGEBLOCK;
      break;
  }

#if defined(_UseVitralMemory)
  pReturn_code = VirtualAlloc(0x00, unActMemsize, MEM_RESERVE | MEM_COMMIT,
                              PAGE_READWRITE);
  if (pReturn_code == (void *)0) {
    return 0;
  }
#elif defined(_WIN32)
  hGlobal = GlobalAlloc(GMEM_FIXED, unActMemsize);
  if (hGlobal == 0) {
    return 0;
  }
  pReturn_code = GlobalLock(hGlobal);
  if (pReturn_code == (void *)0) {
    return 0;
  }
#else
  pReturn_code = mmap(0, unActMemsize, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (pReturn_code == (void *)-1) {
    return 0;
  }
#endif

  pHeap = (struct HeapBlock *)pReturn_code;
  memset(pHeap, 0x00, sizeof(struct HeapBlock));
  pHeapInf = (struct Heapinf *)((char *)pHeap + sizeof(struct HeapBlock));
  unActMemsize -= sizeof(struct HeapBlock);
  if (mode == 0) {
    pHeapInf->unMem_flg = ALLOCATE_ALL_BLOCK;
    pHeapInf->unMem_size = unActMemsize - sizeof(struct Heapinf) * 2;
    pHeapInf = (struct Heapinf *)((char *)pHeapInf + pHeapInf->unMem_size +
                                  sizeof(struct Heapinf));
    pHeapInf->unMem_flg = ALLOCATE_ALL_BLOCK;
    pHeapInf->unMem_size = unActMemsize - sizeof(struct Heapinf) * 2;
  } else {
    pHeapInf->unMem_flg = ALLOCATE_SEP_BLOCK;
    pHeapInf->unMem_size = unActMemsize - sizeof(struct Heapinf) * 2;
    pHeapInf = (struct Heapinf *)((char *)pHeapInf + sizeof(struct Heapinf));
    pHeapInf->unMem_flg = ALLOCATE_STATUS_FREE;
    pHeapInf->unMem_size = unActMemsize - sizeof(struct Heapinf) * 4;
    pHeapInf = (struct Heapinf *)((char *)pHeapInf + pHeapInf->unMem_size +
                                  sizeof(struct Heapinf));
    pHeapInf->unMem_flg = ALLOCATE_STATUS_FREE;
    pHeapInf->unMem_size = unActMemsize - sizeof(struct Heapinf) * 4;
    pHeapInf = (struct Heapinf *)((char *)pHeapInf + sizeof(struct Heapinf));
    pHeapInf->unMem_flg = ALLOCATE_SEP_BLOCK;
    pHeapInf->unMem_size = unActMemsize - sizeof(struct Heapinf) * 2;
  }

  return pReturn_code;
}

struct HeapBlock *hasNext(struct HeapBlock *cur, struct list_head *head,
                          int tid) {
#ifndef _MulThread
  if (cur->list.next == head) {
    return 0;
  }
  return list_entry(cur->list.next, struct HeapBlock, list);
#else
  struct HeapBlock *next = 0;
  lock();
  cur = list_entry(cur->list.next, struct HeapBlock, list);
  for (; &cur->list != head;
       cur = list_entry(cur->list.next, struct HeapBlock, list)) {
    if (cur->tid == tid) {
      next = cur;
      break;
    }
  }
  unlock();
  return next;
#endif
}

static void *_allocate_sub_block(unsigned int unMemAct_size, unsigned int tid) {
  int iMem_flg = 0;
  void *pReturn_code = NULL;
  unsigned int unMemFree_size;
  struct list_head *head = NULL;
  struct HeapBlock *pHeap = NULL;
  struct Heapinf *pHeapInf = NULL;
  struct Heapinf *pWorkInf = NULL;

  head = &_instance->head;

  lock();
  pHeap = list_entry(head->next, struct HeapBlock, list);
  unlock();

  if (unMemAct_size > PAGESIZE) {
    pHeap = (struct HeapBlock *)_allocate_block(
        0,
        unMemAct_size + sizeof(struct HeapBlock) + sizeof(struct Heapinf) * 2);
    if (pHeap != NULL) {
      list_add_tail_safe(&pHeap->list, head);
      pHeap->tid = tid;
      pReturn_code =
          (char *)pHeap + sizeof(struct HeapBlock) + sizeof(struct Heapinf);
    } else {
      ;
    }
    goto EXIT;
  }
  pWorkInf = (struct Heapinf *)((char *)pHeap + sizeof(struct HeapBlock) +
                                sizeof(struct Heapinf));
  do {
    pHeapInf = (struct Heapinf *)((char *)pHeap + sizeof(struct HeapBlock));
    if (pHeap->tid != tid || pHeapInf->unMem_flg == ALLOCATE_ALL_BLOCK) {
      pHeap = hasNext(pHeap, head, tid);
      if (pHeap != NULL) {
        pWorkInf = (struct Heapinf *)((char *)pHeap + sizeof(struct HeapBlock) +
                                      sizeof(struct Heapinf));
      } else {
        pHeap = (struct HeapBlock *)_allocate_block(1, 0);
        if (pHeap != NULL) {
          list_add_tail_safe(&pHeap->list, head);
          pHeap->tid = tid;
          pWorkInf =
              (struct Heapinf *)((char *)pHeap + sizeof(struct HeapBlock) +
                                 sizeof(struct Heapinf));
        } else {
          goto EXIT;
        }
      }
    } else if (pWorkInf->unMem_flg == ALLOCATE_STATUS_FREE) {
      if (pWorkInf->unMem_size >= unMemAct_size + sizeof(struct Heapinf) * 2) {
        unMemFree_size =
            pWorkInf->unMem_size - (unMemAct_size + sizeof(struct Heapinf) * 2);

        pWorkInf->unMem_flg = ALLOCATE_STATUS_USED;
        pWorkInf->unMem_size = unMemAct_size;

        pReturn_code = ((char *)pWorkInf + sizeof(struct Heapinf));
        iMem_flg = 1;

        pWorkInf =
            (struct Heapinf *)((char *)pWorkInf + sizeof(struct Heapinf) +
                               pWorkInf->unMem_size);
        pWorkInf->unMem_flg = ALLOCATE_STATUS_USED;
        pWorkInf->unMem_size = unMemAct_size;

        pWorkInf =
            (struct Heapinf *)((char *)pWorkInf + sizeof(struct Heapinf));
        pWorkInf->unMem_flg = ALLOCATE_STATUS_FREE;
        pWorkInf->unMem_size = unMemFree_size;

        pWorkInf =
            (struct Heapinf *)((char *)pWorkInf + sizeof(struct Heapinf) +
                               pWorkInf->unMem_size);
        pWorkInf->unMem_flg = ALLOCATE_STATUS_FREE;
        pWorkInf->unMem_size = unMemFree_size;
      } else {
        pWorkInf =
            (struct Heapinf *)((char *)pWorkInf + sizeof(struct Heapinf) * 2 +
                               pWorkInf->unMem_size);
      }
    } else if (pWorkInf->unMem_flg == ALLOCATE_STATUS_USED) {
      pWorkInf =
          (struct Heapinf *)((char *)pWorkInf + sizeof(struct Heapinf) * 2 +
                             pWorkInf->unMem_size);
    } else if (pWorkInf->unMem_flg == ALLOCATE_SEP_BLOCK) {
      pHeap = hasNext(pHeap, head, tid);
      if (pHeap != NULL) {
        pWorkInf = (struct Heapinf *)((char *)pHeap + sizeof(struct HeapBlock) +
                                      sizeof(struct Heapinf));
      } else {
        pHeap = (struct HeapBlock *)_allocate_block(1, 0);
        if (pHeap != NULL) {
          list_add_tail_safe(&pHeap->list, head);
          pWorkInf =
              (struct Heapinf *)((char *)pHeap + sizeof(struct HeapBlock) +
                                 sizeof(struct Heapinf));
        } else {
          goto EXIT;
        }
      }
    } else {
      goto EXIT;
    }
  } while (iMem_flg != 1);

EXIT:
  return pReturn_code;
}

void *_allocate(unsigned int ulAreaSize, unsigned int tid) {
  unsigned int unMemAct_size = length_align(ulAreaSize);
  return _allocate_sub_block(unMemAct_size, tid);
}

static void _release_block(struct list_head *head) {
  struct HeapBlock *pHeap, *n;
  struct Heapinf *pHeapInf;
#ifdef _WIN32
  HGLOBAL hGlobal = 0;
#endif
  int free_size;
  pHeap = list_entry(head->next, struct HeapBlock, list);
  n = list_entry(pHeap->list.next, struct HeapBlock, list);
  for (; &pHeap->list != head;
       pHeap = n, n = list_entry(n->list.next, struct HeapBlock, list)) {
    list_del(&pHeap->list);
    pHeapInf = (struct Heapinf *)(pHeap + 1);
    free_size = sizeof(struct HeapBlock) + sizeof(struct Heapinf) * 2 +
                pHeapInf->unMem_size;
#if defined(_UseVitralMemory)
    VirtualFree(pHeap, 0, MEM_RELEASE);
#elif defined(_WIN32)
    hGlobal = GlobalHandle(pHeap);
    GlobalUnlock(hGlobal);
    GlobalFree(hGlobal);
#else
    munmap(pHeap, free_size);
#endif
  }
}

int _is_last(struct list_head *list) {
#ifdef _MulThread
  int pid = 0;
  int count = 0;
  struct list_head *head = NULL;
  struct HeapBlock *pHeap = NULL;
  struct Heapinf *inf = NULL;
  pid = pthread_self();
  head = list;
  lock();
  pHeap = list_entry(head->next, struct HeapBlock, list);
  for (; &pHeap->list != head;
       pHeap = list_entry(pHeap->list.next, struct HeapBlock, list)) {
    if (pHeap->tid == pid) {
      inf = (struct Heapinf *)((char *)pHeap + sizeof(struct HeapBlock));
      if (inf->unMem_flg == ALLOCATE_SEP_BLOCK) {
        if (count++) {
          break;
        }
      }
    }
  }
  unlock();
  if (count == 1) {
    return 1;
  } else {
    return 0;
  }
#else
  if (list->next->next == list->prev) {
    return 1;
  } else {
    return 0;
  }
#endif
}

static int _release_sub_block(void *ptr) {
  int iReturn_code;
  unsigned int unMemFree_size = 0;
  unsigned int unMemNext_free_flg;
  struct list_head *head = NULL;
  struct HeapBlock *pHeap = NULL;
  struct Heapinf *inf = NULL;
  struct Heapinf *pwk_inf = NULL;
#ifdef _WIN32
  HGLOBAL hGlobal = 0;
#endif

  iReturn_code = 0;
  if (ptr == 0) goto EXIT;

  head = &_instance->head;

  inf = (struct Heapinf *)((char *)ptr - sizeof(struct Heapinf));
  switch (inf->unMem_flg) {
    case ALLOCATE_STATUS_USED:
      pwk_inf = inf;
      do {
        pwk_inf = (struct Heapinf *)((char *)pwk_inf + pwk_inf->unMem_size +
                                     sizeof(struct Heapinf) * 2);
        if (pwk_inf->unMem_flg != ALLOCATE_STATUS_FREE &&
            pwk_inf->unMem_flg != ALLOCATE_STATUS_USED &&
            pwk_inf->unMem_flg != ALLOCATE_SEP_BLOCK) {
          iReturn_code = -1;
          goto EXIT;
        }
      } while (pwk_inf->unMem_flg != ALLOCATE_SEP_BLOCK);

      pHeap = (struct HeapBlock *)((char *)pwk_inf - (sizeof(struct HeapBlock) +
                                                      sizeof(struct Heapinf) +
                                                      pwk_inf->unMem_size));

      unMemFree_size = inf->unMem_size;

      pwk_inf = (struct Heapinf *)((char *)inf + inf->unMem_size +
                                   sizeof(struct Heapinf));
      if (pwk_inf->unMem_flg != ALLOCATE_STATUS_USED ||
          pwk_inf->unMem_size != unMemFree_size) {
        iReturn_code = -1;
        goto EXIT;
      }

      unMemNext_free_flg = 0;
      pwk_inf = (struct Heapinf *)((char *)pwk_inf + sizeof(struct Heapinf));
      if (pwk_inf->unMem_flg == ALLOCATE_STATUS_FREE) {
        unMemFree_size += pwk_inf->unMem_size;
        unMemNext_free_flg = 1;
      }

      pwk_inf = (struct Heapinf *)((char *)inf - sizeof(struct Heapinf));
      if (pwk_inf->unMem_flg == ALLOCATE_STATUS_FREE) {
        pwk_inf =
            (struct Heapinf *)((char *)pwk_inf -
                               (pwk_inf->unMem_size + sizeof(struct Heapinf)));
        pwk_inf->unMem_flg = ALLOCATE_STATUS_FREE;
        if (unMemNext_free_flg == 1)
          unMemFree_size =
              pwk_inf->unMem_size + unMemFree_size + sizeof(struct Heapinf) * 4;
        else
          unMemFree_size =
              pwk_inf->unMem_size + unMemFree_size + sizeof(struct Heapinf) * 2;
        pwk_inf->unMem_size = unMemFree_size;
        pwk_inf = (struct Heapinf *)((char *)pwk_inf + unMemFree_size +
                                     sizeof(struct Heapinf));
        pwk_inf->unMem_flg = ALLOCATE_STATUS_FREE;
        pwk_inf->unMem_size = unMemFree_size;
      } else {
        pwk_inf = (struct Heapinf *)((char *)pwk_inf + sizeof(struct Heapinf));
        pwk_inf->unMem_flg = ALLOCATE_STATUS_FREE;
        if (unMemNext_free_flg == 1)
          unMemFree_size += sizeof(struct Heapinf) * 2;
        pwk_inf->unMem_size = unMemFree_size;
        pwk_inf = (struct Heapinf *)((char *)pwk_inf + unMemFree_size +
                                     sizeof(struct Heapinf));
        pwk_inf->unMem_flg = ALLOCATE_STATUS_FREE;
        pwk_inf->unMem_size = unMemFree_size;
      }
      if (_is_last(head)) {
        goto EXIT;
      } else {
        inf = (struct Heapinf *)((char *)pHeap + sizeof(struct HeapBlock));
        if (inf->unMem_size ==
            (inf + 1)->unMem_size + sizeof(struct Heapinf) * 2) {
          ;
        } else {
          goto EXIT;
        }
      }
      break;
    case ALLOCATE_ALL_BLOCK:
      pHeap = (struct HeapBlock *)((char *)inf - sizeof(struct HeapBlock));
      break;
    default:
      iReturn_code = -1;
      goto EXIT;
  }

  lock();
  list_del(&pHeap->list);
  unlock();
#if defined(_UseVitralMemory)
  VirtualFree(pHeap, 0x00, MEM_RELEASE);
#elif defined(_WIN32)
  hGlobal = GlobalHandle(pHeap);
  GlobalUnlock(hGlobal);
  GlobalFree(hGlobal);
#else
  unMemFree_size = ((struct Heapinf *)(pHeap + 1))->unMem_size +
                   sizeof(struct HeapBlock) + sizeof(struct Heapinf) * 2;
  munmap(pHeap, unMemFree_size);
#endif
EXIT:
  return iReturn_code;
}

void _release(void *ptr) { _release_sub_block(ptr); }

void init(struct list_head *head) {}

void createHeapManage() {
  if (_instance == NULL) {
    _instance = (struct HeapInstance *)malloc(sizeof(struct HeapInstance));
    _instance->head.next = _instance->head.prev = &_instance->head;
  }

#ifdef _WIN32
  if (mp_mutex == NULL) {
    mp_mutex = CreateMutex(NULL, FALSE, "heapMutex");
  }
#endif

  struct HeapBlock *pHeap = (struct HeapBlock *)_allocate_block(1, 0);
  if (pHeap != NULL) {
    list_add_tail(&pHeap->list, &_instance->head);
#ifdef _MulThread
    pHeap->tid = pthread_self();
#else
    pHeap->tid = 0;
#endif
  }
}

void destoryHeapManage() {
  if (_instance != 0) {
    _release_block(&_instance->head);
    free((void *)_instance);
    _instance = 0;
  }
}

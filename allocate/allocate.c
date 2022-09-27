#include "allocate.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct HeapLock {
  void *ptr;
  unsigned int lock;
};

struct HeapInf {
  unsigned int unMem_flg;
  unsigned int unMem_size;
};

struct allocate {
  struct allocate *next;
};

struct HeapBlock {
  struct list_head list;
  struct HeapLock *lock;
};

struct HeapInstance {
  struct list_head head;
  struct allocate *lock;
  int lock_num, lock_size;
};

#define BLOCKPAGE (1024 * 128)
#define BLOCKSEP (1024 * 64)
// #define MINIPAGE 1024

#define LOCK_SIZE 128

#define ALLOCATE_ALL_BLOCK 0xFFFFFFFF    // all for block
#define ALLOCATE_SEP_BLOCK 0xEEEEEEEE    // for floated block
#define ALLOCATE_SEP_BLOCK 0xAAAAAAAA    // for fixed block
#define ALLOCATE_STATUS_USED 0x22222222  // used flag
#define ALLOCATE_STATUS_FREE 0x11111111  // unused flag

#define length_align(len) \
  ((len + sizeof(void *) - 1) / sizeof(void *) * sizeof(void *))

static struct HeapInstance *_instance;
static unsigned int lock_allocate = FREE;

#define list_add_tail_safe(ptr, list) \
  {                                   \
    lock(&lock_allocate);             \
    list_add_tail(ptr, list);         \
    unlock(&lock_allocate);           \
  }

int _allocate_lock_free() {
  int lock = 0;
  while (lock++ < 5) {
#ifdef _WIN32
    if (_InterlockedCompareExchange((unsigned long *)&_instance->lock, 0, 0) !=
        0)
    //返回lock_t初始值
#else
    if (__sync_bool_compare_and_swap(&_instance->lock, 0, 0) ==
        0)  //写入新值成功返回1，写入失败返回0
#endif
      return 1;
#ifdef _WIN32
    Sleep(1);
#else
    usleep(1000);
#endif
  }
  return 0;
}

struct allocate *_allocate_lock() {
  void *pReturn_code = NULL;
  struct HeapInf *pHeapInf = NULL;
  lock(&lock_allocate);
  pReturn_code = _instance->lock;
  if (_instance->lock->next == -1) {
    pHeapInf = (char *)_instance - sizeof(struct HeapInf);
    pHeapInf = (char *)pHeapInf + pHeapInf->unMem_size;
    _instance->lock = _instance->lock + sizeof(struct HeapLock);
    if (_instance->lock + sizeof(struct HeapLock) > pHeapInf) {
      _instance->lock = 0;
    }
  } else {
    _instance->lock = _instance->lock->next;
  }
  unlock(&lock_allocate);
}

struct allocate *_release_lock(void *ptr) {
  lock(&lock_allocate);
  ((struct allocate *)ptr)->next = _instance->lock;
  _instance->lock = ptr;
  unlock(&lock_allocate);
}

static void *_allocate_block(int mode, unsigned int unMemSize) {
#ifdef _WIN32
  HGLOBAL hGlobal = 0;
#endif
  void *pReturn_code = NULL;
  struct HeapBlock *pHeap = NULL;
  struct HeapInf *pHeapInf = NULL;
  unsigned int unActMemsize = 0;
  int fd = -1;

  switch (mode) {
    case 0:
      unActMemsize = unMemSize;
      break;
    default:
      unActMemsize = BLOCKPAGE;
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
  pHeapInf = (struct HeapInf *)((char *)pHeap + sizeof(struct HeapBlock));
  unActMemsize -= sizeof(struct HeapBlock);
  if (mode == 0) {
    pHeapInf->unMem_flg = ALLOCATE_ALL_BLOCK;
    pHeapInf->unMem_size = unActMemsize - sizeof(struct HeapInf) * 2;
    pHeapInf = (struct HeapInf *)((char *)pHeapInf + pHeapInf->unMem_size +
                                  sizeof(struct HeapInf));
    pHeapInf->unMem_flg = ALLOCATE_ALL_BLOCK;
    pHeapInf->unMem_size = unActMemsize - sizeof(struct HeapInf) * 2;
  } else {
    pHeapInf->unMem_flg = ALLOCATE_SEP_BLOCK;
    pHeapInf->unMem_size = unActMemsize - sizeof(struct HeapInf) * 2;
    pHeapInf = (struct HeapInf *)((char *)pHeapInf + sizeof(struct HeapInf));
    pHeapInf->unMem_flg = ALLOCATE_STATUS_FREE;
    pHeapInf->unMem_size = unActMemsize - sizeof(struct HeapInf) * 4;
    pHeapInf = (struct HeapInf *)((char *)pHeapInf + pHeapInf->unMem_size +
                                  sizeof(struct HeapInf));
    pHeapInf->unMem_flg = ALLOCATE_STATUS_FREE;
    pHeapInf->unMem_size = unActMemsize - sizeof(struct HeapInf) * 4;
    pHeapInf = (struct HeapInf *)((char *)pHeapInf + sizeof(struct HeapInf));
    pHeapInf->unMem_flg = ALLOCATE_SEP_BLOCK;
    pHeapInf->unMem_size = unActMemsize - sizeof(struct HeapInf) * 2;
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
  lock(&lock_allocate);
  cur = list_entry(cur->list.next, struct HeapBlock, list);
  for (; &cur->list != head;
       cur = list_entry(cur->list.next, struct HeapBlock, list)) {
    if (cur->tid == tid) {
      next = cur;
      break;
    }
  }
  unlock(&lock_allocate);
  return next;
#endif
}

static void *_allocate_sub_block(unsigned int unMemAct_size, unsigned int tid) {
  int iMem_flg = 0;
  void *pReturn_code = NULL;
  unsigned int unMemFree_size;
  struct list_head *head = NULL;
  struct HeapBlock *pHeap = NULL;
  struct HeapInf *pHeapInf = NULL;
  struct HeapInf *pWorkInf = NULL;

  head = &_instance->head;

  lock(&lock_allocate);
  pHeap = list_entry(head->next, struct HeapBlock, list);
  unlock(&lock_allocate);

  if (unMemAct_size > PAGESIZE) {
    pHeap = (struct HeapBlock *)_allocate_block(
        0,
        unMemAct_size + sizeof(struct HeapBlock) + sizeof(struct HeapInf) * 2);
    if (pHeap != NULL) {
      list_add_tail_safe(&pHeap->list, head);
      pHeap->tid = tid;
      pReturn_code =
          (char *)pHeap + sizeof(struct HeapBlock) + sizeof(struct HeapInf);
    } else {
      ;
    }
    goto EXIT;
  }
  pWorkInf = (struct HeapInf *)((char *)pHeap + sizeof(struct HeapBlock) +
                                sizeof(struct HeapInf));
  do {
    pHeapInf = (struct HeapInf *)((char *)pHeap + sizeof(struct HeapBlock));
    if (pHeap->tid != tid || pHeapInf->unMem_flg == ALLOCATE_ALL_BLOCK) {
      pHeap = hasNext(pHeap, head, tid);
      if (pHeap != NULL) {
        pWorkInf = (struct HeapInf *)((char *)pHeap + sizeof(struct HeapBlock) +
                                      sizeof(struct HeapInf));
      } else {
        pHeap = (struct HeapBlock *)_allocate_block(1, 0);
        if (pHeap != NULL) {
          list_add_tail_safe(&pHeap->list, head);
          pHeap->tid = tid;
          pWorkInf =
              (struct HeapInf *)((char *)pHeap + sizeof(struct HeapBlock) +
                                 sizeof(struct HeapInf));
        } else {
          goto EXIT;
        }
      }
    } else if (pWorkInf->unMem_flg == ALLOCATE_STATUS_FREE) {
      if (pWorkInf->unMem_size >= unMemAct_size + sizeof(struct HeapInf) * 2) {
        unMemFree_size =
            pWorkInf->unMem_size - (unMemAct_size + sizeof(struct HeapInf) * 2);

        pWorkInf->unMem_flg = ALLOCATE_STATUS_USED;
        pWorkInf->unMem_size = unMemAct_size;

        pReturn_code = ((char *)pWorkInf + sizeof(struct HeapInf));
        iMem_flg = 1;

        pWorkInf =
            (struct HeapInf *)((char *)pWorkInf + sizeof(struct HeapInf) +
                               pWorkInf->unMem_size);
        pWorkInf->unMem_flg = ALLOCATE_STATUS_USED;
        pWorkInf->unMem_size = unMemAct_size;

        pWorkInf =
            (struct HeapInf *)((char *)pWorkInf + sizeof(struct HeapInf));
        pWorkInf->unMem_flg = ALLOCATE_STATUS_FREE;
        pWorkInf->unMem_size = unMemFree_size;

        pWorkInf =
            (struct HeapInf *)((char *)pWorkInf + sizeof(struct HeapInf) +
                               pWorkInf->unMem_size);
        pWorkInf->unMem_flg = ALLOCATE_STATUS_FREE;
        pWorkInf->unMem_size = unMemFree_size;
      } else {
        pWorkInf =
            (struct HeapInf *)((char *)pWorkInf + sizeof(struct HeapInf) * 2 +
                               pWorkInf->unMem_size);
      }
    } else if (pWorkInf->unMem_flg == ALLOCATE_STATUS_USED) {
      pWorkInf =
          (struct HeapInf *)((char *)pWorkInf + sizeof(struct HeapInf) * 2 +
                             pWorkInf->unMem_size);
    } else if (pWorkInf->unMem_flg == ALLOCATE_SEP_BLOCK) {
      pHeap = hasNext(pHeap, head, tid);
      if (pHeap != NULL) {
        pWorkInf = (struct HeapInf *)((char *)pHeap + sizeof(struct HeapBlock) +
                                      sizeof(struct HeapInf));
      } else {
        pHeap = (struct HeapBlock *)_allocate_block(1, 0);
        if (pHeap != NULL) {
          list_add_tail_safe(&pHeap->list, head);
          pWorkInf =
              (struct HeapInf *)((char *)pHeap + sizeof(struct HeapBlock) +
                                 sizeof(struct HeapInf));
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
  struct HeapInf *pHeapInf;
#ifdef _WIN32
  HGLOBAL hGlobal = 0;
#endif
  int free_size;
  pHeap = list_entry(head->next, struct HeapBlock, list);
  n = list_entry(pHeap->list.next, struct HeapBlock, list);
  for (; &pHeap->list != head;
       pHeap = n, n = list_entry(n->list.next, struct HeapBlock, list)) {
    list_del(&pHeap->list);
    pHeapInf = (struct HeapInf *)(pHeap + 1);
    free_size = sizeof(struct HeapBlock) + sizeof(struct HeapInf) * 2 +
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
  struct HeapInf *inf = NULL;
#ifndef _WIN32
  pid = pthread_self();
#else
  pid = GetCurrentThreadId();
#endif
  head = list;
  lock(&lock_allocate);
  pHeap = list_entry(head->next, struct HeapBlock, list);
  for (; &pHeap->list != head;
       pHeap = list_entry(pHeap->list.next, struct HeapBlock, list)) {
    if (pHeap->tid == pid) {
      inf = (struct HeapInf *)((char *)pHeap + sizeof(struct HeapBlock));
      if (inf->unMem_flg == ALLOCATE_SEP_BLOCK) {
        if (count++) {
          break;
        }
      }
    }
  }
  unlock(&lock_allocate);
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
  struct HeapInf *inf = NULL;
  struct HeapInf *pwk_inf = NULL;
#ifdef _WIN32
  HGLOBAL hGlobal = 0;
#endif

  iReturn_code = 0;
  if (ptr == 0) goto EXIT;

  head = &_instance->head;

  inf = (struct HeapInf *)((char *)ptr - sizeof(struct HeapInf));
  switch (inf->unMem_flg) {
    case ALLOCATE_STATUS_USED:
      pwk_inf = inf;
      do {
        pwk_inf = (struct HeapInf *)((char *)pwk_inf + pwk_inf->unMem_size +
                                     sizeof(struct HeapInf) * 2);
        if (pwk_inf->unMem_flg != ALLOCATE_STATUS_FREE &&
            pwk_inf->unMem_flg != ALLOCATE_STATUS_USED &&
            pwk_inf->unMem_flg != ALLOCATE_SEP_BLOCK) {
          iReturn_code = -1;
          goto EXIT;
        }
      } while (pwk_inf->unMem_flg != ALLOCATE_SEP_BLOCK);

      pHeap = (struct HeapBlock *)((char *)pwk_inf - (sizeof(struct HeapBlock) +
                                                      sizeof(struct HeapInf) +
                                                      pwk_inf->unMem_size));

      unMemFree_size = inf->unMem_size;

      pwk_inf = (struct HeapInf *)((char *)inf + inf->unMem_size +
                                   sizeof(struct HeapInf));
      if (pwk_inf->unMem_flg != ALLOCATE_STATUS_USED ||
          pwk_inf->unMem_size != unMemFree_size) {
        iReturn_code = -1;
        goto EXIT;
      }

      unMemNext_free_flg = 0;
      pwk_inf = (struct HeapInf *)((char *)pwk_inf + sizeof(struct HeapInf));
      if (pwk_inf->unMem_flg == ALLOCATE_STATUS_FREE) {
        unMemFree_size += pwk_inf->unMem_size;
        unMemNext_free_flg = 1;
      }

      pwk_inf = (struct HeapInf *)((char *)inf - sizeof(struct HeapInf));
      if (pwk_inf->unMem_flg == ALLOCATE_STATUS_FREE) {
        pwk_inf =
            (struct HeapInf *)((char *)pwk_inf -
                               (pwk_inf->unMem_size + sizeof(struct HeapInf)));
        pwk_inf->unMem_flg = ALLOCATE_STATUS_FREE;
        if (unMemNext_free_flg == 1)
          unMemFree_size =
              pwk_inf->unMem_size + unMemFree_size + sizeof(struct HeapInf) * 4;
        else
          unMemFree_size =
              pwk_inf->unMem_size + unMemFree_size + sizeof(struct HeapInf) * 2;
        pwk_inf->unMem_size = unMemFree_size;
        pwk_inf = (struct HeapInf *)((char *)pwk_inf + unMemFree_size +
                                     sizeof(struct HeapInf));
        pwk_inf->unMem_flg = ALLOCATE_STATUS_FREE;
        pwk_inf->unMem_size = unMemFree_size;
      } else {
        pwk_inf = (struct HeapInf *)((char *)pwk_inf + sizeof(struct HeapInf));
        pwk_inf->unMem_flg = ALLOCATE_STATUS_FREE;
        if (unMemNext_free_flg == 1)
          unMemFree_size += sizeof(struct HeapInf) * 2;
        pwk_inf->unMem_size = unMemFree_size;
        pwk_inf = (struct HeapInf *)((char *)pwk_inf + unMemFree_size +
                                     sizeof(struct HeapInf));
        pwk_inf->unMem_flg = ALLOCATE_STATUS_FREE;
        pwk_inf->unMem_size = unMemFree_size;
      }
      if (_is_last(head)) {
        goto EXIT;
      } else {
        inf = (struct HeapInf *)((char *)pHeap + sizeof(struct HeapBlock));
        if (inf->unMem_size ==
            (inf + 1)->unMem_size + sizeof(struct HeapInf) * 2) {
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

  lock(&lock_allocate);
  list_del(&pHeap->list);
  unlock(&lock_allocate);
#if defined(_UseVitralMemory)
  VirtualFree(pHeap, 0x00, MEM_RELEASE);
#elif defined(_WIN32)
  hGlobal = GlobalHandle(pHeap);
  GlobalUnlock(hGlobal);
  GlobalFree(hGlobal);
#else
  unMemFree_size = ((struct HeapInf *)(pHeap + 1))->unMem_size +
                   sizeof(struct HeapBlock) + sizeof(struct HeapInf) * 2;
  munmap(pHeap, unMemFree_size);
#endif
EXIT:
  return iReturn_code;
}

void _release(void *ptr) { _release_sub_block(ptr); }

int createHeapManage() {
  int unFreeMemsize = 0;
  struct HeapBlock *pHeap = NULL;
  struct HeapInf *pInf = NULL;
  if (_instance == NULL) {
    pHeap = (struct HeapBlock *)_allocate_block(0, BLOCKPAGE);
    if (pHeap == NULL) {
      return -1;
    }
    pInf = (struct HeapInf *)((char *)pHeap + sizeof(struct HeapBlock));
    unFreeMemsize = pInf->unMem_size - sizeof(struct HeapInstance);

    _instance = (struct HeapInstance *)((char *)pInf + sizeof(struct HeapInf));
    _instance->head.next = _instance->head.prev = &_instance->head;
    _instance->lock = (void *)((char *)_instance + sizeof(struct HeapInstance));
    _instance->lock->next = -1;
    pHeap = (struct HeapBlock *)_allocate_block(1, 0);
    if (pHeap == NULL) {
      return -1;
    }
    list_add_tail(&pHeap->list, &_instance->head);
  }
  return 0;
}

int destoryHeapManage() {
  struct HeapBlock *pHeap = NULL;
#ifdef _WIN32
  HGLOBAL hGlobal = 0;
#endif
  if (_instance != 0) {
    _release_block(&_instance->head);
    pHeap =
        (char *)_instance - sizeof(struct HeapInf) - sizeof(struct HeapBlock);
#if defined(_UseVitralMemory)
    VirtualFree(pHeap, 0, MEM_RELEASE);
#elif defined(_WIN32)
    hGlobal = GlobalHandle(pHeap);
    GlobalUnlock(hGlobal);
    GlobalFree(hGlobal);
#else
    munmap(pHeap, free_size);
#endif
    _instance = 0;
  }
}

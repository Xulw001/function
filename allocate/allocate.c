#include "allocate.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#endif

#include <malloc.h>
#include <stdio.h>
#include <string.h>

#ifndef _WIN32
typedef uintptr_t thrd_t;
#else
typedef DWORD thrd_t;
#endif

struct allocate {
  struct allocate *next;
};

struct HeapInf {
  unsigned int unMem_flg;
  unsigned int unMem_size;
};

struct HeapBlock {
  struct list_head list;
};

struct HeapHead {
  unsigned int offset;
};

struct HeapNext {
  struct list_head list;
};

struct ThreadHeapBlock {
  struct list_head list;
  struct HeapBlock *hb;
  thrd_t tid;
};

struct HeapInstance {
  struct list_head head;
  struct allocate *fix_head[8];
  struct allocate *threads;
  unsigned int lock_allocate;
  unsigned int lock_allocate_fix;
};

#define PAGEHEAP (1024 * 128)
#define PAGESEP (1024 * 64)
#define BLOCKINFOSIZE sizeof(struct HeapBlock) + sizeof(struct HeapInf) * 2
#define BLOCKALLSIZE(n) (n) + (BLOCKINFOSIZE)
#define BLOCKSEP (128)

#define ALLOCATE_ALL_BLOCK 0xFFFFFFFF    // all for block
#define ALLOCATE_SEP_BLOCK 0xEEEEEEEE    // for floated block
#define ALLOCATE_FIX_BLOCK 0xAAAAAAAA    // for fixed block
#define ALLOCATE_STATUS_USED 0x22222222  // used flag
#define ALLOCATE_STATUS_FREE 0x11111111  // unused flag

#define length_align(len) \
  ((len + sizeof(void *) - 1) / sizeof(void *) * sizeof(void *))

static struct HeapInstance *_instance;
static void *_allocate_block(int mode, unsigned int unMemSize);

int _allocate_threadInfo_available() {
  int lock = 0;
  while (lock++ < 5) {
#ifdef _WIN32
    if (_InterlockedCompareExchange((unsigned long *)&_instance->threads, 0,
                                    0) != 0)
#else
    if (__sync_bool_compare_and_swap(&_instance->threads, 0, 0) == 0)
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

struct ThreadHeapBlock *_allocate_threadInfo_block(
    struct HeapInstance *_instance, int tid) {
  struct HeapInf *pHeapInf = NULL;
  struct HeapBlock *pHeap = NULL;
  struct ThreadHeapBlock *pTHeap = NULL;
  lock(&_instance->lock_allocate);
  pTHeap = (struct ThreadHeapBlock *)((char *)_instance->threads);
  if (_instance->threads->next == (struct allocate *)-1) {
    pHeapInf = (struct HeapInf *)((char *)_instance - sizeof(struct HeapInf));
    pHeapInf = (struct HeapInf *)((char *)_instance + pHeapInf->unMem_size);
    _instance->threads = (struct allocate *)((char *)_instance->threads +
                                             sizeof(struct ThreadHeapBlock));
    if ((char *)_instance->threads + sizeof(struct ThreadHeapBlock) >
        (char *)pHeapInf) {
      _instance->threads = 0;
    } else {
      _instance->threads->next = (struct allocate *)-1;
    }
  } else {
    _instance->threads = _instance->threads->next;
  }
  unlock(&_instance->lock_allocate);

  switch (tid) {
    case -1:
#ifndef _WIN32
      pTHeap->tid = pthread_self();
#else
      pTHeap->tid = GetCurrentThreadId();
#endif
      pHeap = (struct HeapBlock *)_allocate_block(2, 0);
      break;
    case 0:
      pTHeap->tid = 0;
      pHeap = (struct HeapBlock *)_allocate_block(1, 0);
      break;
    default:
      pTHeap->tid = tid;
      pHeap = (struct HeapBlock *)_allocate_block(2, 0);
      break;
  }
  if (pHeap == NULL) {
    return 0;
  }
  pHeap->list.next = pHeap->list.prev = &pHeap->list;
  pTHeap->hb = pHeap;
  return pTHeap;
}

void _release_threadInfo_block(void *ptr) {
  lock(&_instance->lock_allocate);
  ((struct allocate *)ptr)->next = _instance->threads;
  _instance->threads = ptr;
  unlock(&_instance->lock_allocate);
}

static void *_allocate_block(int mode, unsigned int unMemSize) {
#ifdef _WIN32
  HGLOBAL hGlobal = 0;
#endif
  void *pReturn_code = NULL;
  struct HeapBlock *pHeap = NULL;
  struct HeapInf *pHeapInf = NULL;
  struct HeapHead *pHeapHead = NULL;
  struct HeapNext *pHeapList = NULL;
  struct HeapNext *pHeapFree = NULL;
  unsigned int unActMemsize = 0;

  switch (mode) {
    case 0:
      unActMemsize = unMemSize;
      break;
    default:
      unActMemsize = PAGEHEAP;
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
  unActMemsize -= sizeof(struct HeapBlock);
  if (mode == 0) {
    // for ALLOCATE_ALL_BLOCK
    pHeapInf = (struct HeapInf *)((char *)pHeap + sizeof(struct HeapBlock));
    pHeapInf->unMem_flg = ALLOCATE_ALL_BLOCK;
    pHeapInf->unMem_size = unActMemsize - sizeof(struct HeapInf) * 2;
    pHeapInf = (struct HeapInf *)((char *)pHeapInf + pHeapInf->unMem_size +
                                  sizeof(struct HeapInf));
    pHeapInf->unMem_flg = ALLOCATE_ALL_BLOCK;
    pHeapInf->unMem_size = unActMemsize - sizeof(struct HeapInf) * 2;
  } else if (mode == 1) {
    pHeapHead = (struct HeapHead *)((char *)pHeap + sizeof(struct HeapBlock));
    pHeapHead->offset = 0;
    pHeapInf = (struct HeapInf *)((char *)pHeapHead + sizeof(struct HeapHead));
    // for ALLOCATE_FIX_BLOCK
    pHeapInf->unMem_flg = ALLOCATE_FIX_BLOCK;
    pHeapInf->unMem_size =
        unActMemsize - sizeof(struct HeapInf) * 2 - sizeof(struct HeapHead);

    pHeapInf = (struct HeapInf *)((char *)pHeapInf + pHeapInf->unMem_size +
                                  sizeof(struct HeapInf));
    pHeapInf->unMem_flg = ALLOCATE_FIX_BLOCK;
    pHeapInf->unMem_size =
        unActMemsize - sizeof(struct HeapInf) * 2 - sizeof(struct HeapHead);
  } else {
    pHeapList = (struct HeapNext *)((char *)pHeap + sizeof(struct HeapBlock));
    // for ALLOCATE_SEP_BLOCK
    pHeapInf = (struct HeapInf *)((char *)pHeapList + sizeof(struct HeapNext));
    pHeapInf->unMem_flg = ALLOCATE_SEP_BLOCK;
    pHeapInf->unMem_size =
        unActMemsize - sizeof(struct HeapInf) * 2 - sizeof(struct HeapNext);
    // for ALLOCATE_STATUS_FREE
    pHeapInf = (struct HeapInf *)((char *)pHeapInf + sizeof(struct HeapInf));
    pHeapInf->unMem_flg = ALLOCATE_STATUS_FREE;
    pHeapInf->unMem_size =
        unActMemsize - sizeof(struct HeapInf) * 4 - sizeof(struct HeapNext);
    // set free_list
    pHeapFree = (struct HeapNext *)((char *)pHeapInf + sizeof(struct HeapInf));
    pHeapFree->list.next = pHeapFree->list.prev = &pHeapList->list;
    pHeapList->list.next = pHeapList->list.prev = &pHeapFree->list;

    pHeapInf = (struct HeapInf *)((char *)pHeapInf + sizeof(struct HeapInf) +
                                  pHeapInf->unMem_size);
    pHeapInf->unMem_flg = ALLOCATE_STATUS_FREE;
    pHeapInf->unMem_size =
        unActMemsize - sizeof(struct HeapInf) * 4 - sizeof(struct HeapNext);
    pHeapInf = (struct HeapInf *)((char *)pHeapInf + sizeof(struct HeapInf));
    pHeapInf->unMem_flg = ALLOCATE_SEP_BLOCK;
    pHeapInf->unMem_size =
        unActMemsize - sizeof(struct HeapInf) * 2 - sizeof(struct HeapNext);
  }

  return pReturn_code;
}

static void *_allocate_sub_block(struct ThreadHeapBlock *ptHeap,
                                 unsigned int unMemAct_size) {
  int iMem_flg = 0;
  void *pReturn_code = NULL;
  unsigned int unMemFree_size;
  struct list_head *head = NULL;
  struct HeapBlock *pHeap = NULL;
  struct HeapNext *pHeapList = NULL;
  struct HeapNext *pHeapfree = NULL;
  struct HeapInf *pHeapInf = NULL;
  struct HeapInf *pWorkInf = NULL;

  pHeap = ptHeap->hb;
  head = &pHeap->list;

  if (unMemAct_size > PAGESEP) {
    pHeap = (struct HeapBlock *)_allocate_block(0, BLOCKALLSIZE(unMemAct_size));
    if (pHeap != NULL) {
      list_add_tail(&pHeap->list, head);
      pReturn_code =
          (char *)pHeap + sizeof(struct HeapBlock) + sizeof(struct HeapInf);
    } else {
      ;
    }
    goto EXIT;
  }

  pHeapList = (struct HeapNext *)((char *)pHeap + sizeof(struct HeapBlock));
  pWorkInf =
      (struct HeapInf *)((char *)pHeapList->list.next - sizeof(struct HeapInf));
  do {
    pHeapInf = (struct HeapInf *)((char *)pHeapList + sizeof(struct HeapNext));
    if (pHeapInf->unMem_flg == ALLOCATE_ALL_BLOCK ||
        pHeapList->list.next ==
            (struct list_head *)((char *)pHeap + sizeof(struct HeapBlock))) {
      if (pHeap->list.next == head) {
        pHeap = (struct HeapBlock *)_allocate_block(2, 0);
        if (pHeap != NULL) {
          list_add_tail(&pHeap->list, head);
        } else {
          goto EXIT;
        }
      } else {
        pHeap = (struct HeapBlock *)(pHeap->list.next);
      }
      pHeapList = (struct HeapNext *)((char *)pHeap + sizeof(struct HeapBlock));
      pWorkInf = (struct HeapInf *)((char *)pHeapList->list.next -
                                    sizeof(struct HeapInf));
    } else if (pWorkInf->unMem_flg == ALLOCATE_STATUS_FREE) {
      if (pWorkInf->unMem_size >= unMemAct_size + sizeof(struct HeapInf) * 2) {
        unMemFree_size =
            pWorkInf->unMem_size - (unMemAct_size + sizeof(struct HeapInf) * 2);

        if (unMemFree_size <= sizeof(struct HeapInf) * 2) {
          unMemAct_size += unMemFree_size;
          unMemFree_size = 0;
        }

        pWorkInf->unMem_flg = ALLOCATE_STATUS_USED;
        pWorkInf->unMem_size = unMemAct_size;

        pReturn_code = ((char *)pWorkInf + sizeof(struct HeapInf));
        pHeapfree = pReturn_code;
        pHeapList = (struct HeapNext *)pHeapfree->list.next;
        list_del(&pHeapfree->list);

        iMem_flg = 1;

        pWorkInf =
            (struct HeapInf *)((char *)pWorkInf + sizeof(struct HeapInf) +
                               pWorkInf->unMem_size);
        pWorkInf->unMem_flg = ALLOCATE_STATUS_USED;
        pWorkInf->unMem_size = unMemAct_size;

        if (unMemFree_size != 0) {
          pWorkInf =
              (struct HeapInf *)((char *)pWorkInf + sizeof(struct HeapInf));
          pWorkInf->unMem_flg = ALLOCATE_STATUS_FREE;
          pWorkInf->unMem_size = unMemFree_size;

          pHeapfree =
              (struct HeapNext *)((char *)pWorkInf + sizeof(struct HeapInf));
          list_add_tail(&pHeapfree->list, &pHeapList->list);

          pWorkInf =
              (struct HeapInf *)((char *)pWorkInf + sizeof(struct HeapInf) +
                                 pWorkInf->unMem_size);
          pWorkInf->unMem_flg = ALLOCATE_STATUS_FREE;
          pWorkInf->unMem_size = unMemFree_size;
        }
      } else {
        pHeapList =
            (struct HeapNext *)((char *)pWorkInf + sizeof(struct HeapInf));
        pWorkInf = (struct HeapInf *)((char *)pHeapList->list.next -
                                      sizeof(struct HeapInf));
      }
    } else {
      goto EXIT;
    }
  } while (iMem_flg != 1);

EXIT:
  return pReturn_code;
}

static void *_allocate_fix_block(struct ThreadHeapBlock *ptHeap,
                                 unsigned int unMemAct_size) {
  int iMem_flg = 0, leaf = 0;
  struct allocate *next, *pReturn_code = NULL;
  struct list_head *head = NULL;
  struct HeapBlock *pHeap = NULL;
  struct HeapInf *pHeapInf = NULL;
  struct HeapHead *pHeapHead = NULL;

  pHeap = ptHeap->hb;
  head = &pHeap->list;
  do {
    pHeapHead = (struct HeapHead *)((char *)pHeap + sizeof(struct HeapBlock));
    pHeapInf = (struct HeapInf *)((char *)pHeapHead + sizeof(struct HeapHead));
    if (pHeapInf->unMem_flg != ALLOCATE_FIX_BLOCK) {
      if (pHeap->list.next == head) {
        pHeap = (struct HeapBlock *)_allocate_block(1, 0);
        if (pHeap != NULL) {
          list_add_tail(&pHeap->list, head);
        } else {
          goto EXIT;
        }
      } else {
        pHeap = (struct HeapBlock *)(pHeap->list.next);
      }
    } else {
      if (pHeapInf->unMem_size < pHeapHead->offset + unMemAct_size) {
        if (pHeap->list.next == head) {
          pHeap = (struct HeapBlock *)_allocate_block(1, 0);
          if (pHeap != NULL) {
            list_add_tail(&pHeap->list, head);
          } else {
            goto EXIT;
          }
        } else {
          pHeap = (struct HeapBlock *)(pHeap->list.next);
        }
      } else if (pHeapInf->unMem_size <
                 pHeapHead->offset + unMemAct_size * 20) {
        pReturn_code =
            (struct allocate *)((char *)pHeapInf + sizeof(struct HeapInf) +
                                pHeapHead->offset);
        leaf = (pHeapInf->unMem_size - pHeapHead->offset) / unMemAct_size;
        pHeapHead->offset = pHeapHead->offset + unMemAct_size * leaf;
        iMem_flg = 1;
      } else {
        pReturn_code =
            (struct allocate *)((char *)pHeapInf + sizeof(struct HeapInf) +
                                pHeapHead->offset);
        leaf = 20;
        pHeapHead->offset = pHeapHead->offset + unMemAct_size * leaf;
        iMem_flg = 1;
      }
    }
  } while (iMem_flg == 0);
EXIT:
  if (leaf > 0) {
    for (int i = 1; i < leaf; i++) {
      next = (struct allocate *)((char *)pReturn_code + unMemAct_size);
      pReturn_code->next = next;
      pReturn_code = next;
    }
    pReturn_code->next = NULL;
    pReturn_code =
        (struct allocate *)((char *)pReturn_code - unMemAct_size * (leaf - 1));
  }

  return pReturn_code;
}

void *_allocate(unsigned int ulAreaSize) {
  int idx = -1, allocate = 0;
  thrd_t tid = 0;
  void *pReturn_code = NULL;
  unsigned int unMemAct_size = 0;
  struct ThreadHeapBlock *ptHeap;
  struct ThreadHeapBlock tHeap;
#ifndef _WIN32
  tid = pthread_self();
#else
  tid = GetCurrentThreadId();
#endif
  unMemAct_size = length_align(ulAreaSize);
  if (unMemAct_size <= BLOCKSEP) {
    if (unMemAct_size > 96) {
      unMemAct_size = 128;
      idx = 7;
    } else if (unMemAct_size > 64) {
      unMemAct_size = 96;
      idx = 6;
    } else if (unMemAct_size > 48) {
      unMemAct_size = 64;
      idx = 5;
    } else if (unMemAct_size > 32) {
      unMemAct_size = 48;
      idx = 4;
    } else if (unMemAct_size > 24) {
      unMemAct_size = 32;
      idx = 3;
    } else if (unMemAct_size > 16) {
      unMemAct_size = 24;
      idx = 2;
    } else if (unMemAct_size > 8) {
      unMemAct_size = 16;
      idx = 1;
    } else {
      unMemAct_size = 8;
      idx = 0;
    }
  Retry:
    lock(&_instance->lock_allocate_fix);
    if (_instance->fix_head[idx] != NULL) {
      pReturn_code = _instance->fix_head[idx];
      if (_instance->fix_head[idx]->next != NULL) {
        _instance->fix_head[idx] = _instance->fix_head[idx]->next;
        allocate = 0;
      } else {
        allocate = 1;
      }
    } else {
      allocate = 1;
    }
    unlock(&_instance->lock_allocate_fix);
    tid = 0;
    if (!allocate) {
      return pReturn_code;
    }
  }
  // First Thread Block, can't modfiy by any thread
  ptHeap = (struct ThreadHeapBlock *)_instance->head.next;
  tHeap = *ptHeap;
  for (;;) {
    if (tHeap.tid == tid) {
      if (tid == 0) {
        lock(&_instance->lock_allocate_fix);
        if (_instance->fix_head[idx] == NULL) {
          _instance->fix_head[idx] = _allocate_fix_block(ptHeap, unMemAct_size);
        }
        unlock(&_instance->lock_allocate_fix);
        if (pReturn_code) {
          return pReturn_code;
        }
        goto Retry;
      } else {
        return _allocate_sub_block(ptHeap, unMemAct_size);
      }
    }
    if (tHeap.list.next == &_instance->head) {
      while (_allocate_threadInfo_available() == 0)
        ;
      ptHeap = _allocate_threadInfo_block(_instance, tid);
      if (ptHeap == NULL) {
        return NULL;
      }
      lock(&_instance->lock_allocate);
      list_add_tail(&ptHeap->list, &_instance->head);
      unlock(&_instance->lock_allocate);
    }
    lock(&_instance->lock_allocate);
    ptHeap = (struct ThreadHeapBlock *)ptHeap->list.next;
    tHeap = *ptHeap;
    unlock(&_instance->lock_allocate);
  };
}

static void _release_block(struct ThreadHeapBlock *thb) {
  int final = 0;
  struct HeapBlock *pHeap, *n;
  struct HeapInf *pHeapInf;
#ifdef _WIN32
  HGLOBAL hGlobal = 0;
#endif
  int free_size;
  pHeap = (struct HeapBlock *)thb->hb->list.next;
  n = (struct HeapBlock *)pHeap->list.next;
  do {
    if (n != thb->hb) {
      list_del(&pHeap->list);
    } else {
      final = 1;
    }
#if defined(_UseVitralMemory)
    VirtualFree(pHeap, 0, MEM_RELEASE);
#elif defined(_WIN32)
    hGlobal = GlobalHandle(pHeap);
    GlobalUnlock(hGlobal);
    GlobalFree(hGlobal);
#else
    pHeapInf = (struct HeapInf *)((char *)pHeap + sizeof(struct HeapBlock));
    free_size = BLOCKINFOSIZE + pHeapInf->unMem_size;
    munmap(pHeap, free_size);
#endif
    if (final) break;

    pHeap = n;
    n = (struct HeapBlock *)pHeap->list.next;
  } while (TRUE);
  lock(&_instance->lock_allocate);
  list_del(&thb->list);
  unlock(&_instance->lock_allocate);
  _release_threadInfo_block(thb);
}

void _release_thread_block() {
  thrd_t tid = 0;
  struct ThreadHeapBlock *ptHeap;
  struct ThreadHeapBlock tHeap;
#ifndef _WIN32
  tid = pthread_self();
#else
  tid = GetCurrentThreadId();
#endif

  // First Thread Block, can't modfiy by any thread
  ptHeap = (struct ThreadHeapBlock *)_instance->head.next;
  tHeap = *ptHeap;
  for (;;) {
    if (tHeap.list.next == &_instance->head) {
      break;
    }
    if (tHeap.tid == tid) {
      _release_block(ptHeap);
      break;
    }
    lock(&_instance->lock_allocate);
    ptHeap = (struct ThreadHeapBlock *)ptHeap->list.next;
    tHeap = *ptHeap;
    unlock(&_instance->lock_allocate);
  };
}

static int _release_sub_block(struct ThreadHeapBlock *pTHeap, void *ptr) {
  int iReturn_code;
  unsigned int unMemFree_size = 0;
  unsigned int unMemNext_free_flg;
  struct list_head *head = NULL;
  struct HeapBlock *pHeap = NULL;
  struct HeapInf *inf = NULL;
  struct HeapInf *pwk_inf = NULL;
  struct HeapNext *pHeapList = NULL;
  struct HeapNext *pHeapFree = NULL;
#ifdef _WIN32
  HGLOBAL hGlobal = 0;
#endif

  iReturn_code = 0;

  head = &pTHeap->hb->list;

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
      } while (pwk_inf->unMem_flg == ALLOCATE_STATUS_USED);

      if (pwk_inf->unMem_flg == ALLOCATE_SEP_BLOCK) {
        pHeapList =
            (struct HeapNext *)((char *)pwk_inf - (sizeof(struct HeapInf) +
                                                   sizeof(struct HeapNext) +
                                                   pwk_inf->unMem_size));
        pHeap =
            (struct HeapBlock *)((char *)pHeapList - sizeof(struct HeapBlock));
      } else {
        pHeapList =
            (struct HeapNext *)((char *)pwk_inf + sizeof(struct HeapInf));
      }

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

        pHeapFree = pHeapList;
        pHeapList = (struct HeapNext *)pHeapFree->list.next;
        list_del(&pHeapFree->list);
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
        pwk_inf = inf;
        pwk_inf->unMem_flg = ALLOCATE_STATUS_FREE;
        if (unMemNext_free_flg == 1)
          unMemFree_size += sizeof(struct HeapInf) * 2;
        pwk_inf->unMem_size = unMemFree_size;

        pHeapFree =
            (struct HeapNext *)((char *)pwk_inf + sizeof(struct HeapInf));
        list_add_tail(&pHeapFree->list, &pHeapList->list);

        pwk_inf = (struct HeapInf *)((char *)pwk_inf + unMemFree_size +
                                     sizeof(struct HeapInf));
        pwk_inf->unMem_flg = ALLOCATE_STATUS_FREE;
        pwk_inf->unMem_size = unMemFree_size;
      }
      inf = pwk_inf;
      pwk_inf = (struct HeapInf *)((char *)inf - sizeof(struct HeapInf));
      if (pwk_inf->unMem_flg != ALLOCATE_SEP_BLOCK ||
          pwk_inf->unMem_size != inf->unMem_size + sizeof(struct HeapInf) * 2) {
        goto EXIT;
      } else {
        pHeap =
            (struct HeapBlock *)((char *)pwk_inf - sizeof(struct HeapBlock));
        if (pHeap->list.next == head) {
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

  list_del(&pHeap->list);
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

void _release(void *ptr, int size) {
  int idx = -1;
  thrd_t tid = 0;
  unsigned int unMemAct_size = 0;
  struct ThreadHeapBlock *ptHeap;
  struct ThreadHeapBlock tHeap;
#ifndef _WIN32
  tid = pthread_self();
#else
  tid = GetCurrentThreadId();
#endif
  if (ptr == NULL) {
    return;
  }

  unMemAct_size = length_align(size);
  if (unMemAct_size != -1 && unMemAct_size <= BLOCKSEP) {
    if (unMemAct_size > 96) {
      idx = 7;
    } else if (unMemAct_size > 64) {
      idx = 6;
    } else if (unMemAct_size > 48) {
      idx = 5;
    } else if (unMemAct_size > 32) {
      idx = 4;
    } else if (unMemAct_size > 24) {
      idx = 3;
    } else if (unMemAct_size > 16) {
      idx = 2;
    } else if (unMemAct_size > 8) {
      idx = 1;
    } else {
      idx = 0;
    }
    lock(&_instance->lock_allocate_fix);
    ((struct allocate *)ptr)->next = _instance->fix_head[idx];
    _instance->fix_head[idx] = ptr;
    unlock(&_instance->lock_allocate_fix);
  }
  // First Thread Block, can't modfiy by any thread
  ptHeap = (struct ThreadHeapBlock *)_instance->head.next;
  tHeap = *ptHeap;
  for (;;) {
    if (tHeap.tid == tid) {
      _release_sub_block(ptHeap, ptr);
      break;
    }
    lock(&_instance->lock_allocate);
    ptHeap = (struct ThreadHeapBlock *)ptHeap->list.next;
    tHeap = *ptHeap;
    unlock(&_instance->lock_allocate);
  };
}

int createHeapManage() {
  struct HeapBlock *pHeap = NULL;
  struct ThreadHeapBlock *pTHeap = NULL;
  struct HeapInf *pInf = NULL;
  if (_instance == NULL) {
    pHeap = (struct HeapBlock *)_allocate_block(0, BLOCKALLSIZE(PAGEHEAP));
    if (pHeap == NULL) {
      return -1;
    }
    pInf = (struct HeapInf *)((char *)pHeap + sizeof(struct HeapBlock));

    _instance = (struct HeapInstance *)((char *)pInf + sizeof(struct HeapInf));
    _instance->head.next = _instance->head.prev = &_instance->head;
    _instance->lock_allocate = FREE;
    _instance->lock_allocate_fix = FREE;
    _instance->threads =
        (void *)((char *)_instance + sizeof(struct HeapInstance));
    _instance->threads->next = (struct allocate *)-1;
    for (int i = 0; i < 8; i++) {
      _instance->fix_head[i] = NULL;
    }
    pTHeap = _allocate_threadInfo_block(_instance, 0);
    if (pTHeap == NULL) {
      return -1;
    }
    list_add_tail(&pTHeap->list, &_instance->head);
    pTHeap = _allocate_threadInfo_block(_instance, -1);
    if (pTHeap == NULL) {
      return -1;
    }
    list_add_tail(&pTHeap->list, &_instance->head);
  }
  return 0;
}

int destoryHeapManage() {
  struct HeapBlock *pHeap = NULL;
  struct ThreadHeapBlock *pTHeap = NULL;
#ifdef _WIN32
  HGLOBAL hGlobal = 0;
#endif
  if (_instance != 0) {
    pTHeap = (struct ThreadHeapBlock *)_instance->head.next;
    while ((struct ThreadHeapBlock *)&_instance->head != pTHeap) {
      _release_block(pTHeap);
      pTHeap = (struct ThreadHeapBlock *)_instance->head.next;
    }
    pHeap = (struct HeapBlock *)((char *)_instance - sizeof(struct HeapInf) -
                                 sizeof(struct HeapBlock));
#if defined(_UseVitralMemory)
    VirtualFree(pHeap, 0, MEM_RELEASE);
#elif defined(_WIN32)
    hGlobal = GlobalHandle(pHeap);
    GlobalUnlock(hGlobal);
    GlobalFree(hGlobal);
#else
    munmap(pHeap, BLOCKALLSIZE(PAGEHEAP));
#endif
    _instance = 0;
  }
}

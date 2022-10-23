/*
 * Copyright (c) 2021,xulw. All Rights Reserved.
 */
#pragma once
#include "common_type.h"

#ifndef _list_head_init
#define list_head_init(name) \
  { &(name), &(name) }
#endif

#if !defined(offsetof) && !defined(_offsetof)
#define offsetof(TYPE, MEMBER) ((size_t) & (((TYPE *)0)->MEMBER))
#endif

#ifndef _container_of
#define container_of(ptr, type, member) \
  (type *)((char *)ptr - offsetof(type, member))
#endif

#define list_entry(ptr, type, member) container_of(ptr, type, member)

#ifdef __cplusplus
template <typename T>
inline T const &MIN(T const &a, T const &b) {
  return a < b ? a : b;
}

template <typename T>
inline T const &MAX(T const &a, T const &b) {
  return a > b ? a : b;
}

template <typename T>
inline bool COMPARE(T const &a, T const &b) {
  return a > b ? true : false;
}

template <typename T>
inline void swap(T *a, T *b) {
  const T arr = *a;
  *a = *b;
  *b = arr;
}

template <typename T>
inline T ABS(T val) {
  if (val >= 0) return val;
  return ~(val - 1);
}

static inline void __list_del(struct list_head *prev, struct list_head *next) {
  next->prev = prev;
  prev->next = next;
}

static inline void list_del(struct list_head *_ptr) {
  __list_del(_ptr->prev, _ptr->next);
  _ptr->prev = 0;
  _ptr->next = 0;
}

static inline void __list_add(struct list_head *_ptr, struct list_head *prev,
                              struct list_head *next) {
  next->prev = _ptr;
  _ptr->next = next;
  _ptr->prev = prev;
  prev->next = _ptr;
}

static inline void list_add(struct list_head *_ptr, struct list_head *head) {
  __list_add(_ptr, head, head->next);
}

static inline void list_add_tail(struct list_head *_ptr,
                                 struct list_head *head) {
  __list_add(_ptr, head->prev, head);
}
#else
#define __list_del(p, n) \
  {                      \
    n->prev = p;         \
    p->next = n;         \
  }

#define list_del(_ptr)                      \
  {                                         \
    __list_del((_ptr)->prev, (_ptr)->next); \
    (_ptr)->prev = 0;                       \
    (_ptr)->next = 0;                       \
  }

#define list_add_tail(_ptr, list) \
  {                               \
    (_ptr)->prev = (list)->prev;  \
    (_ptr)->next = (list);        \
    (list)->prev->next = (_ptr);  \
    (list)->prev = (_ptr);        \
  }

#endif

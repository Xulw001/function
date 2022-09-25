#pragma once

struct Node {
  struct Node *next;
  void *val;
  int hash;
};

struct TreeNode {
  struct Node *left, *right;
  void *val;
  int hash;
};

struct map {
  struct map_item *entry;
  int capacity;
  int factor;
  int threshold;
  int size;
};

struct map* Map(int cap);
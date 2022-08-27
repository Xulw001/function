#include "hash.h"

#include <string.h>

uint BKDRHash(const char *key, int len) {
  uint h = 0;
  int seed = 31;
  for (int i = 0; key[i] != '\0' || i < len; i++) {
    h = seed * h + key[i];
  }
  return h;
}

uint APHash(const char *key, int len) {
  uint h = 0xAAAAAAAA;
  for (int i = 0; key[i] != '\0' || i < len; i++) {
    h ^= (i & 1) ? (~((h << 11) ^ (key[i]) ^ (h >> 5)))
                 : ((h << 7) ^ (key[i]) ^ (h >> 3));
  }
  return h;
}

uint DJBHash(const char *key, int len) {
  uint h = 5831;
  for (int i = 0; key[i] != '\0' || i < len; i++) {
    h = (h << 5) + h + key[i];
  }
  return h;
}

uint JSHash(const char *key, int len) {
  uint h = 1315423911;
  for (int i = 0; key[i] != '\0' || i < len; i++) {
    h ^= ((h << 5) + key[i] + (h >> 2));
  }
  return h;
}

uint RSHash(const char *key, int len) {
  uint b = 378551;
  uint a = 63689;
  uint h = 0;

  for (int i = 0; key[i] != '\0' || i < len; i++) {
    h = h * a + key[i];
    a *= b;
  }

  return h;
}

uint SDBMHash(const char *key, int len) {
  uint h = 0;

  for (int i = 0; key[i] != '\0' || i < len; i++) {
    h = key[i] + (h << 6) + (h << 16) - h;
  }

  return h;
}

uint PJWHash(const char *key, int len) {
  const uint BitsInUnsignedInt = (uint)(sizeof(uint) * 8);
  const uint ThreeQuarters = (uint)((BitsInUnsignedInt * 3) / 4);
  const uint OneEighth = (uint)(BitsInUnsignedInt / 8);
  const uint HighBits = (uint)(0xFFFFFFFF) << (BitsInUnsignedInt - OneEighth);
  uint h = 0;
  uint t = 0;

  for (int i = 0; key[i] != '\0' || i < len; i++) {
    h = (h << OneEighth) + key[i];

    if ((t = h & HighBits) != 0) {
      h = ((h ^ (t >> ThreeQuarters)) & (~HighBits));
    }
  }

  return h;
}

uint ELFHash(const char *key, int len) {
  uint h = 0;
  uint x = 0;

  for (int i = 0; key[i] != '\0' || i < len; i++) {
    h = (h << 4) + key[i];

    if ((x = h & 0xF0000000L) != 0) {
      h ^= (x >> 24);
    }

    h &= ~x;
  }

  return h;
}

uint DEKHash(const char *key, int len) {
  uint i = 0;
  uint h = len ? len : strlen(key);

  for (int i = 0; key[i] != '\0' || i < len; i++) {
    h = ((h << 5) ^ (h >> 27)) ^ (key[i]);
  }

  return h;
}

// Form MurmurHash3 MurmurHash3_x86_32
//-----------------------------------------------------------------------------
// Block read - if your platform needs to do endian-swapping or can only
// handle aligned reads, do the conversion here

union platform {
  uint a;
  char b;
} x = {1};

#define swapint(a)                                                           \
  ((a << 24 & 0xFF000000) | (a >> 24 & 0x000000FF) | (a << 8 & 0x00FF0000) | \
   (a >> 8 & 0x0000FF00))

// x右移r位 将高r位移动至低位
#define ROTL32(x, r) ((x << r) | (x >> (32 - r)))

uint getblock32(const uint *p, int i) {
  if (x.b) {
    return p[i];
  } else {
    return swapint(p[i]);
  }
}

uint fmix32(uint h) { return h; }

uint MurmurHash(const char *key, int len) {
  const uint8_t *data = (const uint8_t *)key;
  const int nblocks = len / 4;

  uint h1 = 0x97c29b3a;

  const uint c1 = 0xcc9e2d51;
  const uint c2 = 0x1b873593;

  //----------
  // body
  // 4个char组成uint类型进行hash
  const uint *blocks = (const uint *)(data + nblocks * 4);

  for (int i = -nblocks; i; i++) {
    uint k1 = getblock32(blocks, i);

    k1 *= c1;
    k1 = ROTL32(k1, 15);
    k1 *= c2;

    h1 ^= k1;
    h1 = ROTL32(h1, 13);
    h1 = h1 * 5 + 0xe6546b64;
  }

  //----------
  // tail
  // 剩余char进行hash
  const uint8_t *tail = (const uint8_t *)(data + nblocks * 4);
  uint k1 = 0;
  switch (len & 3) {
    case 3:
      k1 ^= tail[2] << 16;
    case 2:
      k1 ^= tail[1] << 8;
    case 1:
      k1 ^= tail[0];
      k1 *= c1;
      k1 = ROTL32(k1, 15);
      k1 *= c2;
      h1 ^= k1;
  };

  //----------
  // finalization
  h1 ^= len;
  // force all bits of a hash block to avalanche
  h1 ^= h1 >> 16;
  h1 *= 0x85ebca6b;
  h1 ^= h1 >> 13;
  h1 *= 0xc2b2ae35;
  h1 ^= h1 >> 16;

  return h1;
}
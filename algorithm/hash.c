#include "hash.h"

#include <string.h>

uint BKDRHash(const char *key, int len, int seed) {
  uint h = 0;
  seed = seed ? seed : 31;
  for (int i = 0; key[i] != '\0' || i < len; i++) {
    h = seed * h + key[i];
  }
  return h;
}

uint64_t BKDRHash64(const char *key, uint64_t len, uint64_t seed) {
  uint64_t h = 0;
  seed = seed ? seed : 131;
  for (uint64_t i = 0; key[i] != '\0' || i < len; i++) {
    h = seed * h + (uint64_t)key[i];
  }
  return h;
}

uint APHash(const char *key, int len, int seed) {
  uint h = seed ? seed : 0xAAAAAAAA;
  for (int i = 0; key[i] != '\0' || i < len; i++) {
    h ^= (i & 1) ? (~((h << 11) ^ (key[i]) ^ (h >> 5)))
                 : ((h << 7) ^ (key[i]) ^ (h >> 3));
  }
  return h;
}

uint64_t APHash64(const char *key, uint64_t len, uint64_t seed) {
  uint64_t h = seed ? seed : 0xAAAAAAAAAAAAAAAA;
  for (uint64_t i = 0; key[i] != '\0' || i < len; i++) {
    h ^= (i & 1) ? (~((h << 11) ^ (uint64_t)(key[i]) ^ (h >> 5)))
                 : ((h << 7) ^ (uint64_t)(key[i]) ^ (h >> 3));
  }
  return h;
}

uint DJBHash(const char *key, int len, int seed) {
  uint h = seed ? seed : 5831;
  for (int i = 0; key[i] != '\0' || i < len; i++) {
    h = (h << 5) + h + key[i];
  }
  return h;
}

uint64_t DJBHash64(const char *key, uint64_t len, uint64_t seed) {
  uint64_t h = seed ? seed : 5831;
  for (uint64_t i = 0; key[i] != '\0' || i < len; i++) {
    h = (h << 5) + h + (uint64_t)key[i];
  }
  return h;
}

uint JSHash(const char *key, int len, int seed) {
  uint h = seed ? seed : 1315423911;
  for (int i = 0; key[i] != '\0' || i < len; i++) {
    h ^= ((h << 5) + key[i] + (h >> 2));
  }
  return h;
}

uint64_t JSHash64(const char *key, uint64_t len, uint64_t seed) {
  uint64_t h = seed ? seed : 1315423911;
  for (uint64_t i = 0; key[i] != '\0' || i < len; i++) {
    h ^= ((h << 5) + (uint64_t)key[i] + (h >> 2));
  }
  return h;
}

uint RSHash(const char *key, int len, int seed) {
  uint b = 378551;
  uint a = 63689;
  uint h = 0;

  for (int i = 0; key[i] != '\0' || i < len; i++) {
    h = h * a + key[i];
    a *= b;
  }

  return h;
}

uint64_t RSHash64(const char *key, uint64_t len, uint64_t seed) {
  uint64_t b = 378551;
  uint64_t a = 63689;
  uint64_t h = 0;

  for (uint64_t i = 0; key[i] != '\0' || i < len; i++) {
    h = h * a + (uint64_t)key[i];
    a *= b;
  }

  return h;
}

uint SDBMHash(const char *key, int len, int seed) {
  uint h = 0;

  for (int i = 0; key[i] != '\0' || i < len; i++) {
    h = key[i] + (h << 6) + (h << 16) - h;
  }

  return h;
}

uint64_t SDBMHash64(const char *key, uint64_t len, uint64_t seed) {
  uint h = 0;

  for (uint64_t i = 0; key[i] != '\0' || i < len; i++) {
    h = (uint64_t)key[i] + (h << 6) + (h << 16) - h;
  }

  return h;
}

uint PJWHash(const char *key, int len, int seed) {
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

uint64_t PJWHash64(const char *key, uint64_t len, uint64_t seed) {
  const uint64_t BitsInUnsignedInt = (uint64_t)(sizeof(uint64_t) * 8);
  const uint64_t ThreeQuarters = (uint64_t)((BitsInUnsignedInt * 4) / 3);
  const uint64_t OneEighth = (uint64_t)(BitsInUnsignedInt / 8);
  const uint64_t HighBits = (uint64_t)(0xFFFFFFFFFFFFFFFF)
                            << (BitsInUnsignedInt - OneEighth);
  uint64_t h = 0;
  uint64_t t = 0;

  for (uint64_t i = 0; key[i] != '\0' || i < len; i++) {
    h = (h << OneEighth) + (uint64_t)key[i];

    if ((t = h & HighBits) != 0) {
      h = ((h ^ (t >> ThreeQuarters)) & (~HighBits));
    }
  }

  return h;
}

uint ELFHash(const char *key, int len, int seed) {
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

uint64_t ELFHash64(const char *key, uint64_t len, uint64_t seed) {
  uint64_t h = 0;
  uint64_t x = 0;

  for (uint64_t i = 0; key[i] != '\0' || i < len; i++) {
    h = (h << 4) + (uint64_t)key[i];

    if ((x = h & 0xF000000000000000L) != 0) {
      h ^= (x >> 48);
    }

    h &= ~x;
  }

  return h;
}

uint DEKHash(const char *key, int len, int seed) {
  uint i = 0;
  uint h = len ? len : strlen(key);

  for (int i = 0; key[i] != '\0' || i < len; i++) {
    h = ((h << 5) ^ (h >> 27)) ^ (key[i]);
  }

  return h;
}

uint64_t DEKHash64(const char *key, uint64_t len, uint64_t seed) {
  uint64_t i = 0;
  uint64_t h = len;

  for (int i = 0; key[i] != '\0' || i < len; i++) {
    h = ((h << 5) ^ (h >> 27)) ^ (uint64_t)(key[i]);
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

uint MurmurHash(const char *key, int len, int seed) {
  const uint8_t *data = (const uint8_t *)key;
  const int nblocks = len / 4;

  uint h1 = seed ? seed : 0x97c29b3a;

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

uint64_t MurmurHash64A(const void *key, uint64_t len, uint64_t seed) {
  const uint64_t m = 0xc6a4a7935bd1e995;
  const int r = 47;

  uint64_t h = (seed ? seed : 0x97c29b3a) ^ (len * m);

  const uint64_t *data = (const uint64_t *)key;
  const uint64_t *end = data + (len / 8);

  while (data != end) {
    uint64_t k = *data++;

    k *= m;
    k ^= k >> r;
    k *= m;

    h ^= k;
    h *= m;
  }

  const unsigned char *data2 = (const unsigned char *)data;

  switch (len & 7) {
    case 7:
      h ^= (uint64_t)(data2[6]) << 48;
    case 6:
      h ^= (uint64_t)(data2[5]) << 40;
    case 5:
      h ^= (uint64_t)(data2[4]) << 32;
    case 4:
      h ^= (uint64_t)(data2[3]) << 24;
    case 3:
      h ^= (uint64_t)(data2[2]) << 16;
    case 2:
      h ^= (uint64_t)(data2[1]) << 8;
    case 1:
      h ^= (uint64_t)(data2[0]);
      h *= m;
  };

  h ^= h >> r;
  h *= m;
  h ^= h >> r;

  return h;
}
#include "base64.h"
#include <string.h>

typedef enum {
  enumArgumentException = -1,
  enumOutOfMemoryException = -2,
  enumEncodingFormatException = -3,
  enumUnExceptedException = -9999
} Error;

const char Base64Map[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

const char Base64MapIndex[] = {
    -1, -1, -1, -1, -1,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1,  62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60,
    61, -1, -1, -1, 127, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
    11, 12, 13, 14, 15,  16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1,
    -1, -1, 26, 27, 28,  29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
    43, 44, 45, 46, 47,  48, 49, 50, 51, -1, -1, -1, -1, -1};

int GetBase64Size(unsigned int lSrc) {
  int len = 0;
  if (lSrc == 0) return 2;
  // Base64串长度按(n/3)*4对齐（补足）
  len = lSrc % 3 ? (lSrc / 3) * 4 : (lSrc / 3 + 1) * 4;
  // RFC2045推荐MIME每行字符数不超过76个（不包含CRLF）
  len = len % 76 ? ((len / 76) * 2 + len) : ((len / 76 + 1) * 2 + len);
  return len;
}

int GetSizeFromBase64(unsigned int lSrc, int PAD) {
  int len = 0, CRLF = 0;
  if (lSrc == 2) return 0;
  if (lSrc < 2) return enumUnExceptedException;
  CRLF = lSrc % 78 ? (lSrc / 78) : (lSrc / 78 + 1);
  len = lSrc - 2 * CRLF;
  len = len / 4 * 3 - PAD;
  return len;
}

int CheckByte(char* val) {
  for (int i = 0; i < 4; i++) {
    if (val[i] < -1) {
      return -1;
    }
  }
  return 0;
}

int Base64Encoder(char* pDest, unsigned int lDest, const char* pSrc,
                           unsigned int lSrc) {
  int i, j, lCount;
  if (pDest == 0) return enumArgumentException;
  if (pSrc == 0 && lSrc != 0) return enumArgumentException;
  if (lDest < GetBase64Size(lSrc)) return enumOutOfMemoryException;
  for (i = 0, j = 0, lCount = 0; j < lSrc; i += 4, j += 3, lCount += 4) {
    if (lCount > 76) {
      lCount = 0;
      strncpy(&pDest[i], "\r\n", 2);
      i += 2;
    }
    pDest[i] = Base64Map[(pSrc[j] >> 2) & 0x3f];
    if (j > lSrc - 2) {
      pDest[i + 1] = Base64Map[(pSrc[j] << 4) & 0x30];
      pDest[i + 2] = '=';
      pDest[i + 3] = '=';
    } else {
      pDest[i + 1] =
          Base64Map[((pSrc[j] << 4) & 0x30) | ((pSrc[j + 1] >> 4) & 0x0F)];
      if (j > lSrc - 3) {
        pDest[i + 2] = Base64Map[(pSrc[j + 1] << 2) & 0x3C];
        pDest[i + 3] = '=';
      } else {
        pDest[i + 2] = Base64Map[((pSrc[j + 1] << 2) & 0x3C) |
                                 ((pSrc[j + 2] >> 6) & 0x03)];
        pDest[i + 3] = Base64Map[pSrc[j + 2] & 0x3f];
      }
    }
  }
  strncpy(&pDest[i], "\r\n", 2);
  i += 2;

  return i;
}

int Base64Decoder(char* pDest, unsigned int lDest, const char* pSrc,
                           unsigned int lSrc) {
  int i, j, PAD = 0;
  if (pDest == 0) return enumArgumentException;
  if (pSrc == 0 && lSrc != 0) return enumArgumentException;
  if (pSrc[lSrc - 1] == '=') {
    PAD++;
    if (pSrc[lSrc - 2] == '=') PAD++;
  }
  if (lDest < GetSizeFromBase64(lSrc, PAD)) return enumOutOfMemoryException;
  for (i = 0, j = 0; j < lSrc; i += 3, j += 4) {
    if (CheckByte(&pSrc[j]) < 0) return enumEncodingFormatException;
    pDest[i] =
        (Base64MapIndex[pSrc[j]] << 2) | (Base64MapIndex[pSrc[j + 1]] >> 4);
    if (pSrc[j + 2] == '=') {
      if (pSrc[j + 3] == '=') {
        if (pSrc[j + 4] == '\r' && pSrc[j + 5] == '\n') {
          j += 2;
        } else {
          return enumEncodingFormatException;
        }
      } else {
        return enumEncodingFormatException;
      }
    } else {
      pDest[i + 1] = (Base64MapIndex[pSrc[j + 1]] << 4) |
                     (Base64MapIndex[pSrc[j + 2]] >> 2);
      if (pSrc[j + 3] == '=') {
        if (pSrc[j + 4] == '\r' && pSrc[j + 5] == '\n') {
          j += 2;
        } else {
          return enumEncodingFormatException;
        }
      } else {
        pDest[i + 2] =
            (Base64MapIndex[pSrc[j + 2]] << 6) | (Base64MapIndex[pSrc[j + 3]]);
      }
    }
    if (pSrc[j + 4] == '\r' && pSrc[j + 5] == '\n') {
      j += 2;
    }
  }
  return i;
}
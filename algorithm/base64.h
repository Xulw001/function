#pragma once
#ifdef __cplusplus
extern "C" {
#endif
int GetBase64Size(unsigned int lSrc);

int GetSizeFromBase64(unsigned int lSrc, int PAD);

int CheckByte(char* val);

int Base64Encoder(char* pDest, unsigned int lDest, const char* pSrc,
                  unsigned int lSrc);

int Base64Decoder(char* pDest, unsigned int lDest, const char* pSrc,
                  unsigned int lSrc);
#ifdef __cplusplus
}
#endif
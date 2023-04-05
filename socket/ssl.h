#pragma once
#include <openssl/err.h>
#include <openssl/ossl_typ.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "socket.h"

#ifndef _WIN32
#define SSL_Close(ssl, fd)                                     \
  if (ssl != NULL) {                                           \
    do {                                                       \
      int ret = SSL_shutdown(ssl);                             \
      if (ret == 0) {                                          \
        ret = SSL_shutdown(ssl);                               \
      }                                                        \
      if (ret != 1) {                                          \
        SslErr(__FILE__, __LINE__, __errno(), "SSL_shutdown"); \
      }                                                        \
    } while (0);                                               \
    SSL_free(ssl);                                             \
  }                                                            \
  close(fd);
#else
#define SSL_Close(ssl, fd)                                     \
  if (ssl != NULL) {                                           \
    do {                                                       \
      int ret = SSL_shutdown(ssl);                             \
      if (ret == 0) {                                          \
        ret = SSL_shutdown(ssl);                               \
      }                                                        \
      if (ret != 1) {                                          \
        SslErr(__FILE__, __LINE__, __errno(), "SSL_shutdown"); \
      }                                                        \
    } while (0);                                               \
    SSL_free(ssl);                                             \
  }                                                            \
  closesocket(fd);
#endif

typedef struct {
  SSL_CTX* ctx;
  SSL* ssl;
  void* psock;
} ssl_channel;

int InitSSL(Socket* pSocket);
int InitSSLSocket(Socket* pSocket, int flag);
int SslCheck(SSL* ssl, int ret);
int SslErr(char* file, int line, int err, char* fun);
int OptVerify(SSL_EXTEND_OPT* opt, X509_VERIFY_PARAM* vpm);
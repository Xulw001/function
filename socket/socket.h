#pragma once
#ifndef _WIN32
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#ifdef _TEST_DEBUG
#include <stdio.h>
#endif

#ifndef _WIN32
typedef unsigned int SOCKET;
typedef struct sockaddr* PSOCKADDR;
typedef struct addrinfo ADDRINFOT;
#endif

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 64
#endif

#ifndef BACKLOG
#define BACKLOG 10
#endif

#ifndef MAX_LISTEN_THREAD
#define MAX_LISTEN_THREAD 2
#endif

#ifndef _WIN32
#define INVALID_SOCKET -1
#endif

#ifdef _WIN32
#define __errno() GetLastError()
#else
#define __errno() errno
#endif

#ifndef _WIN32
#define Close(fd) close(fd)
#else
#define Close(fd) closesocket(fd)
#endif

#define FULLRPSMSG "server is full, please wait for some minutes"

typedef enum {
  _SSLV23,
  _TLSV1,
  _TLSV11,
  _TLSV12,
  _DTLS,
  _DTLSV1,
  _DTLSV12,
} SSL_VER;

typedef enum {
  _SSL_VER_NONE,
  _SSL_VER_PEER,
  _SSL_VER_PEER_UPPER,
} SSL_VERIFY;

typedef enum {
  _SSL_CA_NO = 0x10,
  _SSL_CA_DEFAULT = 0x20,
  _SSL_CA_NATVE = 0x30,
  _SSL_CA_PATH = 0x40,
  _SSL_CA_FILE = 0x50,
  _SSL_CA_ALL = 0x60
} SSL_CA;

typedef struct {
  char* OPT_V_POLICY;
  char* OPT_V_PURPOSE;
  char* OPT_V_VERIFY_NAME;
  char* OPT_V_ATTIME;
  char* OPT_V_VERIFY_HOSTNAME;
  char* OPT_V_VERIFY_EMAIL;
  char* OPT_V_VERIFY_IP;
  char OPT_V_VERIFY_DEPTH;
  char OPT_V_VERIFY_AUTH_LEVEL;
  char OPT_V_IGNORE_CRITICAL;
  char OPT_V_ISSUER_CHECKS;
  char OPT_V_CRL_CHECK;
  char OPT_V_CRL_CHECK_ALL;
  char OPT_V_POLICY_CHECK;
  char OPT_V_EXPLICIT_POLICY;
  char OPT_V_INHIBIT_ANY;
  char OPT_V_INHIBIT_MAP;
  char OPT_V_X509_STRICT;
  char OPT_V_EXTENDED_CRL;
  char OPT_V_USE_DELTAS;
  char OPT_V_POLICY_PRINT;
  char OPT_V_CHECK_SS_SIG;
  char OPT_V_TRUSTED_FIRST;
  char OPT_V_SUITEB_128_ONLY;
  char OPT_V_SUITEB_128;
  char OPT_V_SUITEB_192;
  char OPT_V_PARTIAL_CHAIN;
  char OPT_V_NO_ALT_CHAINS;
  char OPT_V_NO_CHECK_TIME;
  char OPT_V_ALLOW_PROXY_CERTS;
  char OPT_V_RESV;
} SSL_EXTEND_OPT;

typedef enum {
  PEM = 1,
  ASN1,
} SSL_FILE_VER;

typedef enum {
  SSLVER,
  VERIFY,
  CERTFILE,
  EXTEND,
} ssl_option;

typedef struct {
  SSL_VER ver;
  SSL_VERIFY verify;
  SSL_CA caopt;
  SSL_FILE_VER filever;
  char* cCAPath;   // CA Path
  char* cCAFile;   // CA File
  char* certfile;  // Certificate File
  char* keyfile;   // Private Key File
  char* keypass;   // Private Key File Passwd
  SSL_EXTEND_OPT* opt;
} ssl_info;

typedef enum { UDP, NOBLOCK, TLS, AIO } option;

typedef struct {
  char udp_flg;  // 0: default 1: UDP
  char nio_flg;  // 0: default 1: no block
  char ssl_flg;  // 0: default 1: SSL/TLS/DTLS
  char aio_flg;  // 0: default 1: Win/IOCP Linux/epoll
  char resv1[3];
  char resv2;
} socket_option;

typedef struct {
  char host[HOST_NAME_MAX];
  int timeout;
  int port;
} socket_info;

typedef struct {
  void* fd;
  socket_option opt;
  socket_info info;
  ssl_info sslInfo;
} Socket;

typedef int (*SendCallback)(unsigned channel, int port, char* pBuf, unsigned size);
typedef int (*RecvCallback)(unsigned channel, int port, char* pBuf, unsigned size);

int InitSocket(Socket* socket);
int SetSocketInfo(Socket* socket, const char* host, unsigned port,
                  unsigned timeout);
int SetSocketOption(Socket* socket, option opt, int val);
int SetSSLOption(Socket* socket, ssl_option opt, ...);
int SocketSend(Socket* socket, char* buff, unsigned size);
int SocketRecv(Socket* socket, char* buff, unsigned size);
int SocketBind(Socket* socket, RecvCallback pRecv, SendCallback pSend);
int EndSocket(Socket* socket);

int Select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds,
           int timeout);

#ifdef _TEST_DEBUG
#ifndef ERROUT
#define ERROUT(fun, err)                                                       \
  printf("error appear at %s:%d in %s, errno = %d\n", __FILE__, __LINE__, fun, \
         err)

#define WARNING(fun) \
  printf("warning appear at %s:%d in %s\n", __FILE__, __LINE__, fun)
#endif
#else
#define ERROUT(fun, err) ;
#define WARNING(fun) ;
#endif
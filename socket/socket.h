#pragma once
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif
#include <openssl/err.h>
#include <openssl/ossl_typ.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#ifdef _DEBUG
#include <stdio.h>
#endif

#ifndef _WIN32
typedef unsigned int SOCKET;
typedef struct sockaddr* PSOCKADDR;
typedef struct addrinfo ADDRINFOT;
#endif

#ifndef MAX_CONNECT
#define MAX_CONNECT 64
#endif

#ifndef CT_NUM
#define CT_NUM (1)
#endif

#ifndef BACKLOG
#define BACKLOG 10
#endif

#ifndef _WIN32
#define INVALID_SOCKET -1
#endif

#ifdef _WIN32
#define __errno() GetLastError()
#else
#define __errno() errno
#endif

#define MSGBUF_32K 1024 * 32

#define HOSTLEN 64

typedef enum {
  _CS_IDLE,
  _CS_REQ_STARTED,
  _CS_REQ_SENT,
  _CS_REQ_RECV,
  _CS_LISTEN,
} State;

typedef enum {
  SOCKET_CLOSE = -99,
  SOCKET_DOWN,
  IO_ERR = -9,  //
  MEMORY_ERR,   //
  SSL_ERR,      //
  SELECT_ERR,   //
  BIND_ERR,     //
  CONNECT_ERR,  //
  STATE_ERR,    //
  WAS_ERR,      //
  OPT_ERR       // hostname exception
} InterError;

typedef enum {
  _SSLV23_CLIENT,
  _SSLV23_SERVER,
  _TLSV1_CLIENT,
  _TLSV1_SERVER,
  _TLSV11_CLIENT,
  _TLSV11_SERVER,
  _TLSV12_CLIENT,
  _TLSV12_SERVER,
  _DTLS_CLIENT = 10,
  _DTLS_SERVER,
  _DTLSV1_CLIENT,
  _DTLSV1_SERVER,
  _DTLSV12_CLIENT,
  _DTLSV12_SERVER,
} SSL_VER;

typedef enum {
  _SSL_VER_NONE,
  _SSL_CLI_VER_PEER,
  _SSL_SVR_VER_PEER,
  _SSL_SVR_VER_PEER_UPPER,
} SSL_VERIFY;

typedef enum {
  _SSL_CA_NO = 0x00010000,
  _SSL_CA_DEFAULT = 0x00020000,
  _SSL_CA_NATVE = 0x00030000,
  _SSL_CA_PATH = 0x00040000,
  _SSL_CA_FILE = 0x00050000,
  _SSL_CA_ALL = 0x00060000
} SSL_CA;

typedef SSL* (*callback)(void*, SOCKET fd, SSL* ssl_fd);

typedef struct {
  char udp_flg;  // TCP/UDP
  char nag_flg;  // 0: default 1: close Nagle 2: user decide
  char cls_flg;  // 0: default 1: clean socket buff
  char ssl_flg;  // SSL/TLS 0: open 1: SSL/TLS/DTLS
  char aio_flg;  // Win/IOCP Linux/epoll
  char resv[3];
  int timeout;
  int port;
  char* host;
} socket_option;

typedef struct {
  SOCKET fd;
  int shutdown;
  int tasknum;
  int tasklock;
} socket_st;

typedef struct {
  int use;
  socket_st st[MAX_CONNECT];
} socket_fd;

typedef struct {
  SSL* ssl[MAX_CONNECT];
  char p_flg[MAX_CONNECT];  // 0:prepare 1:ready 2:complete
} socket_ssl_fd;

typedef struct {
  SSL_CTX* ctx;
  SSL* ssl;
  socket_ssl_fd* fds;
  char p_flg;
} socket_ssl;

typedef struct {
  int r, w;
  char p[0];
} socket_buff;

typedef struct {
  SOCKET fd;
  State state;
  socket_option opt;
  socket_buff* buf;
  socket_ssl* ssl_st;
  socket_fd* client;
} socket_base;

typedef struct {
  socket_base* mSocket;
  int (*fin)(void*);
  int (*send)(void*, const char*, int);
  int (*recv)(void*, const char*, int);
  int (*load_cert_file)(void*, int, int, int, int, ...);
#ifndef _SOCKET_SERVER
  int (*connect)(void*);
  int (*ssl_connect)(void*);
#else
  char* heloMsg;
  SSL* (*callback)(void*, SOCKET, SSL*);
  int (*listen)(void*);
  SSL* (*ssl_bind)(void*, SOCKET fd);
#endif
} socket_function;

socket_function* initClient(socket_option* opt);
socket_function* initServer(socket_option* opt, callback cb, char* msg);
int final(socket_function* fun);
int __connect(socket_function* owner);
int __close(socket_function* owner, int group, int idx);
int __fin(socket_function* owner);
int __send(socket_function* owner, const char* buf, int size);
int __recv(socket_function* owner, const char* buf, int size);
int __load_cert_file(socket_function* owner, int sslV, int verifyCA, int filev,
                     int args, ...);
int __bind(socket_function* owner);
int __ssl_listen(socket_function* owner);
SSL* __ssl_bind(socket_function* owner, SOCKET fd);

#define IsEmpty(buf) ((buf->r == 0) && (buf->w == -1))
int __open(socket_function* owner);
int __close0(socket_function* owner);
int __ssl_connect(socket_function* owner);
int __optchk(socket_option* opt);
int __sslErr(char* file, int line, int err, char* fun);
int __sslChk(SSL* ssl_st, int ret);

int __bio_read(socket_base* socket, char* buf, int size);
int __bio_write(socket_base* socket, char* buf, int size);
int __bio_listen(socket_function* owner);
#ifndef _WIN32
u_int __bio_commucation(void* params);
#else
u_int __stdcall __bio_commucation(void* params);
#endif
int __bio_sub_commucation(int* final, void* params);

#ifdef _DEBUG
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

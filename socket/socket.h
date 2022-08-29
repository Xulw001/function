#pragma once
#ifdef _WIN32
#include <openssl/err.h>
#include <openssl/ossl_typ.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif
#ifdef _DEBUG
#include <stdio.h>
#endif

#ifndef _WIN32
typedef unsigned int SOCKET;
typedef struct sockaddr* PSOCKADDR;
typedef struct addrinfo ADDRINFOT;
#endif

#ifndef MAX_CONNECT
#define MAX_CONNECT (1024)
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

typedef enum {
  _CS_IDLE,
  _CS_REQ_STARTED,
  _CS_REQ_SENT,
  _CS_REQ_RECV,
  _CS_LISTEN,
  _CS_BADEND
} State;

typedef enum {
  OPT_FLG = -1,      //
  OPT_PORT = -2,     // 通信端口异常
  OPT_HOST = -3,     // 主机名未指定
  WAS_VER = -4,      //
  STATE_ERR = -5,    //
  CONNECT_ERR = -6,  //
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
} SSLVER;

typedef int (*callbackstart)(SOCKET fd, PSOCKADDR addrinfo);
typedef int (*callback)(SOCKET fd, int nread);

typedef struct {
  char udp_flg;  // TCP/UDP
  char nio_flg;  // block/noblock
  char nag_flg;  // 0: 正常socket 1: 关闭Nagle算法 2: 自定义发送
  char cls_flg;  // 0: 正常socket 1: 清空读缓冲
  char ssl_flg;  // SSL/TLS通信 0: open 1: SSL/TLS
  char aio_flg;  // Win/IOCP Linux/epoll
  char resv[2];
  int timeout;
  int port;
  char* host;
} socket_option;

struct socket_fd {
  struct socket_fd* next;
  SOCKET* cfd;
};

struct socket_ssl_fd {
  struct socket_ssl_fd* next;
  SSL* ssl;
  char p_flg;  // 0:准备,1:就绪,2:完成
};

typedef struct {
  SSL_CTX* ctx;
  char* key_file;
  char* cert_file;
  struct socket_ssl_fd fds;
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
  struct socket_fd* client;
} socket_base;

typedef struct {
  socket_base* mSocket;
  int (*connect)(void*);
  int (*close)(void*);
  int (*fin)(void*);
  int (*send)(void*, const char*, int);
  int (*recv)(void*, const char*, int);
  int (*load_cert_file)(void*, const char*, const char*, int, int);
  int (*ssl_connect)(void*);
} socket_function;

// typedef struct {
//   socket_base* mSocket;
//   int (*bind)(void*);
//   int (*listen)(void*);
//   int (*ssl_bind)(void*);
//   int (*callback)(SOCKET fd, int nread);
//   int (*callbackstart)(SOCKET fd, PSOCKADDR addrinfo);
//   int (*close)(void*);
// } socket_function_server;

// socket_function_server* initServer(socket_option* opt, callback cb,
//                                    callbackstart start);
// int finalServer(socket_function_server* fun);
socket_function* initClient(socket_option* opt);
int __connect(socket_function* owner);
int __close(socket_function* owner);
int __fin(socket_function* owner);
int __send(socket_function* owner, const char* buf, int size);
int __recv(socket_function* owner, const char* buf, int size);
int __load_cert_file(socket_function* owner, const char* key_file,
                     const char* cert_file, int sslV, int filev);

#define IsEmpty(buf) ((buf->r == 0) && (buf->w == -1))
int __open(socket_function* owner);
int __ssl_connect(socket_function* owner);
int __sslErr(char* file, int line, char* fun);

int __bio_read(SOCKET fd, const char* buf, int size);
int __bio_write(SOCKET fd, const char* buf, int size);

// int finalClient(socket_function* fun);

// #ifdef _Server
// #define socket_function socket_function
// #define init(opt, cb, start) initServer(opt, cb, start)
// #else
// #define socket_function socket_function_server
// #define init(opt) initClient(opt)
// #endif

// // Client :: No public for User
// int final(void* fun);
// int __open(socket_function* owner);
// int __optchk(socket_option* opt);
// int __load_cert_file(socket_function* owner, const char* key_file,
//                      const char* cert_file, int sslV, int filev);
// int __sslErr(char* file, int line, char* fun);
// int __sslChk(SSL* ssl_st, int ret);

// int __connect(socket_function* owner);
// int __close0(socket_function* owner);
// int __fin(socket_function* owner);
// int __send(socket_function* owner, const char* buf, int size);
// int __recv(socket_function* owner, const char* buf, int size);
// int __bio_read(socket_function* owner, int* err);
// int __bio_write(socket_function* owner, int* err);
// int __ssl_connect(socket_function* owner);

// int __bind(socket_function_server* owner);
// int __listen(socket_function_server* owner);
// int __close1(socket_function_server* owner);
// int __closeClient(socket_function_server* owner, int index, int group);
// int __ssl_bind(socket_function_server* owner, int index, int group);
#ifdef _DEBUG
#ifndef ERROUT
#define ERROUT(fun, err)                                                     \
  printf("error appear at %s:%d in %s, errno = %d", __FILE__, __LINE__, fun, \
         err)

#define WARNING(fun) \
  printf("warning appear at %s:%d in %s", __FILE__, __LINE__, fun)
#endif
#else
#define ERROUT(fun, err) ;
#define WARNING(fun) ;
#endif
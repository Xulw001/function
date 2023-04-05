#include "server.h"
#ifndef _WIN32
#include <pthread.h>
#else
#include <process.h>
#include <windows.h>
#endif
#include <stdio.h>
#include <thread/lock.h>

#ifndef _WIN32
#define thrd_t pthread_t
#else
#define thrd_t uintptr_t
#endif

int UDPBind(Socket* socket, RecvCallback pRecv, SendCallback pSend) {
  int errRet = 0;
  thrd_t mthread[MAX_LISTEN_THREAD];
  if (pRecv == NULL || pSend == NULL) {
    return 0;
  }
  if (socket->fd == NULL) {
    errRet = InitServer(socket);
    if (errRet) {
      return errRet;
    }

#ifndef _WIN32
    u_int (*__fun_listen)(void* params);
#else
    u_int (*__stdcall __fun_listen)(void* params);
#endif

    if (socket->opt.aio_flg) {
      __fun_listen = AsyncListen;
    } else {
      __fun_listen = UDPListen;
    }

    for (int i = 0; i < MAX_LISTEN_THREAD; i++) {
#ifndef _WIN32
      if (pthread_create(&mthread[i], NULL, __fun_listen, (void*)socket->fd) !=
          0)
#else
      if ((mthread[i] = _beginthreadex(NULL, 0, __fun_listen, (void*)socket->fd,
                                       0, 0)) == 0)
#endif
      {
        ERROUT("pthread_create", __errno());
        goto ERR;
      }
    }
  }

  ((channel_extend*)socket->fd)->pRecv = pRecv;
  ((channel_extend*)socket->fd)->pSend = pSend;

  return 0;
ERR:
  if (socket->fd != NULL) {
    // TODO delete socket
  }
  return -1;
}

u_int UDPListen(void* pSocket) {
  channel_extend* socket = pSocket;
  int err;
  SOCKET cfd;
  struct timeval tvTimeOut;
  sockaddr_info cliAddr;
#define MSGBUF_8K 1024 * 8
  char sbuf[MSGBUF_8K];
  int size = 0;
  int slen = 0;

  while (socket->state == _CS_IDLE) {
    slen = sizeof(cliAddr);
    lock(&socket->mutex);
    size = recvfrom(socket->fd, sbuf, MSGBUF_8K, 0, (struct sockaddr*)&cliAddr,
                    &slen);
    unlock(&socket->mutex);
    if (size < 0) {
      err = __errno();
      if (socket->noblock != 1 || (err != EAGAIN && err != EWOULDBLOCK)) {
        ERROUT("recvfrom", err);
      }
      continue;
    }

    err = socket->pRecv(cliAddr.v4.sin_addr.s_addr, cliAddr.v4.sin_port, sbuf,
                        size);
    if (err < 0) {
      continue;
    }

    do {
      size = socket->pSend(cliAddr.v4.sin_addr.s_addr, cliAddr.v4.sin_port,
                           sbuf, MSGBUF_8K);
      if (size <= 0) {
        break;
      }

      do {
        err =
            sendto(socket->fd, sbuf, size, 0, (struct sockaddr*)&cliAddr, slen);
        if (err < 0) {
          err = __errno();
          if (!socket->noblock ||
              (err != EINTR && err != EAGAIN && err != EWOULDBLOCK)) {
            ERROUT("send", err);
            break;
          }
          continue;
        }
      } while (err < 0);
    } while (MSGBUF_8K <= size);
  }

  socket->state = _CS_END;
  return 0;
}

SOCKET UDPSocket(sockaddr_info* svrAddr, sockaddr_info* cliAddr) {
  SOCKET fd = INVALID_SOCKET;
  int option = 0;
  fd = socket(cliAddr->ss.ss_family, SOCK_DGRAM, 0);
  if (fd == INVALID_SOCKET) {
    ERROUT("socket", __errno());
    return -1;
  }

  option = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*)&option,
                 (socklen_t)sizeof(option)) != 0) {
    ERROUT("setsockopt", __errno());
    goto Err;
  }

#if defined(SO_REUSEPORT) && !defined(__linux__)
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void*)&option,
                 (socklen_t)sizeof(option) != 0)) {
    ERROUT("setsockopt", __errno());
    goto Err;
  }
#endif

  switch (cliAddr->ss.ss_family) {
    case AF_INET:
      if (bind(fd, (const struct sockaddr*)svrAddr,
               sizeof(struct sockaddr_in)) < 0) {
        ERROUT("bind", __errno());
        goto Err;
      }
      if (connect(fd, (struct sockaddr*)cliAddr, sizeof(struct sockaddr_in)) <
          0) {
        ERROUT("connect", __errno());
        goto Err;
      }
      break;
    case AF_INET6:
      option = 0;
      setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&option, sizeof(option));
      if (bind(fd, (const struct sockaddr*)svrAddr,
               sizeof(struct sockaddr_in6)) < 0) {
        ERROUT("bind", __errno());
        goto Err;
      }
      if (connect(fd, (struct sockaddr*)cliAddr, sizeof(struct sockaddr_in6)) <
          0) {
        ERROUT("connect", __errno());
        goto Err;
      }
      break;
    default:
      break;
  }

  return fd;
Err:
  Close(fd);
  return -1;
}

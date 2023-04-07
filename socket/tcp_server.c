#include "server.h"
#ifndef _WIN32
#include <pthread.h>
#else
#include <process.h>
#include <windows.h>
#endif
#include <thread/lock.h>

#ifndef _WIN32
#define thrd_t pthread_t
#else
#define thrd_t uintptr_t
#endif

int TCPBind(Socket* socket, RecvCallback pRecv, SendCallback pSend) {
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
      __fun_listen = TCPListen;
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

u_int TCPListen(void* pSocket) {
  channel_extend* socket = pSocket;
  int err;
  fd_set fds;
  int nfds, maxfd;
  int used = 1, next;
  SOCKET cfd, fd[MAX_CONNECT];
  struct timeval tvTimeOut;
  sockaddr_info cliAddr;

  memset(fd, INVALID_SOCKET, sizeof(fd));
  fd[0] = socket->fd;
  while (socket->state == _CS_IDLE) {
    maxfd = 0;
    next = used;
    FD_ZERO(&fds);
    for (int i = 0, j = 0; i < MAX_CONNECT && j < used; i++) {
      if (fd[i] != INVALID_SOCKET) {
        FD_SET(fd[i], &fds);
        if (maxfd < fd[i]) {
          maxfd = fd[i];
        }
        j++;
      } else {
        next = i;
      }
    }
    tvTimeOut.tv_sec = socket->timeout;
    tvTimeOut.tv_usec = 0;
    lock(&socket->mutex);
    nfds = select(maxfd + 1, &fds, NULL, NULL, &tvTimeOut);
    if (nfds <= 0) {
      unlock(&socket->mutex);
      if (nfds < 0) {
        ERROUT("select", __errno());
      }
      continue;
    }

    if (FD_ISSET(socket->fd, &fds)) {
      nfds--;
      err = sizeof(cliAddr);
      cfd = accept(socket->fd, (PSOCKADDR)&cliAddr, &err);
      unlock(&socket->mutex);
      if (cfd < 0) {
        err = __errno();
        if (socket->noblock != 1 || (err != EAGAIN && err != EWOULDBLOCK)) {
          ERROUT("accept", err);
        }
        continue;
      }

      if (used >= MAX_CONNECT) {
        WARNING("accept when socket queue is full");
        err = send(cfd, FULLRPSMSG, sizeof(FULLRPSMSG), 0);
        if (err < 0) {
          ERROUT("send", err);
        }
        Close(cfd);
        continue;
      }

      if (socket->noblock == 1) {
        u_long option = 1;
#ifndef _WIN32
        if (ioctl(cfd, FIONBIO, &option))
#else
        if (ioctlsocket(cfd, FIONBIO, &option))
#endif
        {
          ERROUT("ioctl", __errno());
          Close(cfd);
          continue;
        }
      }

      err = CallBack(cfd, socket->pRecv, socket->pSend, socket->noblock, 1);
      if (err != 0) {
        Close(cfd);
        continue;
      }
      fd[next] = cfd;
      used++;
    }
    if (socket->mutex == LOCK) {
      unlock(&socket->mutex);
    }
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    for (int i = 1; i < MAX_CONNECT && 0 < nfds; i++) {
      if (FD_ISSET(fd[i], &fds)) {
        nfds--;
        err = CallBack(fd[i], socket->pRecv, socket->pSend, socket->noblock, 0);
        if (err != 0) {
          Close(fd[i]);
          fd[i] = INVALID_SOCKET;
          used--;
        }
      }
    }
  }

  for (int i = 1, j = 1; i < MAX_CONNECT && j < used; i++) {
    if (fd[i] != INVALID_SOCKET) {
      Close(fd[i]);
      fd[i] = INVALID_SOCKET;
      j++;
    }
  }

  socket->state = _CS_END;
  return 0;
}

int CallBack(SOCKET fd, RecvCallback pRecv, SendCallback pSend, int noblock,
             int init) {
  int err;
  int size;
#define MSGBUF_8K 1024 * 8
  char sbuf[MSGBUF_8K];

  if (!init) {
    do {
      size = recv(fd, sbuf, MSGBUF_8K, 0);
      if (size == 0) {
        return 1;  // socket close
      } else if (size < 0) {
        err = __errno();
#ifdef _WIN32
        if (noblock && err == WSAEWOULDBLOCK) continue;
#else
        if (noblock && (err == EAGAIN || err == EWOULDBLOCK)) continue;
#endif
        ERROUT("recv", err);
        return -1;  // socket error
      }
      err = pRecv(fd, 0, sbuf, size);
      if (err < 0) {
        return err;
      }
    } while (MSGBUF_8K <= size);
  }

  do {
    size = pSend(fd, 0, sbuf, MSGBUF_8K);
    if (size <= 0) {
      return size;
    }

    do {
      err = send(fd, sbuf, size, 0);
      if (err < 0) {
        err = __errno();
        if (noblock && (err == EINTR || err == EAGAIN || err == EWOULDBLOCK)) {
          continue;
        }
        ERROUT("send", err);
        return -1;
      }
    } while (err < 0);
  } while (MSGBUF_8K <= size);

  return 0;
}
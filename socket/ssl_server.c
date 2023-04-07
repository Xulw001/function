#include "ssl_server.h"
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

int UDPSSLBind(Socket* socket, RecvCallback pRecv, SendCallback pSend) {
  int errRet = 0;
  thrd_t mthread[MAX_LISTEN_THREAD];
  if (pRecv == NULL || pSend == NULL) {
    return 0;
  }
  if (socket->fd == NULL) {
    errRet = InitSSLServer(socket);
    if (errRet) {
      return errRet;
    }

#ifndef _WIN32
    u_int (*__fun_listen)(void* params);
#else
    u_int (*__stdcall __fun_listen)(void* params);
#endif

    if (socket->opt.aio_flg) {
      __fun_listen = AsyncSSLListen;
    } else {
      __fun_listen = UDPSSLListen;
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

  ((channel_extend*)((ssl_channel*)socket->fd)->psock)->pRecv = pRecv;
  ((channel_extend*)((ssl_channel*)socket->fd)->psock)->pSend = pSend;

  return 0;
ERR:
  if (socket->fd != NULL) {
    // TODO delete socket
  }
  return -1;
}

int SSLBind(Socket* socket, RecvCallback pRecv, SendCallback pSend) {
  int errRet = 0;
  thrd_t mthread[MAX_LISTEN_THREAD];
  if (pRecv == NULL || pSend == NULL) {
    return 0;
  }
  if (socket->fd == NULL) {
    errRet = InitSSLServer(socket);
    if (errRet) {
      return errRet;
    }

#ifndef _WIN32
    u_int (*__fun_listen)(void* params);
#else
    u_int (*__stdcall __fun_listen)(void* params);
#endif

    if (socket->opt.aio_flg) {
      __fun_listen = AsyncSSLListen;
    } else {
      __fun_listen = SSLListen;
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

  ((channel_extend*)((ssl_channel*)socket->fd)->psock)->pRecv = pRecv;
  ((channel_extend*)((ssl_channel*)socket->fd)->psock)->pSend = pSend;

  return 0;
ERR:
  if (socket->fd != NULL) {
    // TODO delete socket
  }
  return -1;
}

int InitSSLServer(Socket* pSocket) {
  int err = 0;
  ssl_channel* pssl = NULL;
  channel_extend* psock = NULL;

  err = InitSSLSocket(pSocket, 0);
  if (err) {
    return err;
  }
  pssl = pSocket->fd;

  err = InitServer(pSocket);
  if (err) {
    return err;
  }
  psock = pSocket->fd;
  pssl->psock = psock;
  pSocket->fd = pssl;
  return 0;
}

int EndSSLServer(Socket* socket) {
  int err = 0;
  if (socket->fd != NULL) {
    channel_extend* channel = ((ssl_channel*)socket->fd)->psock;
    while (channel->state != _CS_END) {
#ifdef _WIN32
      Sleep(1000);
#else
      sleep(1);
#endif
    }
    Close(channel->fd);
    free(channel);
    ((ssl_channel*)socket->fd)->psock = NULL;
    free(socket->fd);
    socket->fd = NULL;
  }
  return 0;
}

SSL* SSLAccept(SOCKET fd, SSL_CTX* ctx) {
  int err;
  SSL* ssl;
  if (fd == 0 || ctx == NULL) {
    ERROUT("SSLAccept failed with nullptr!", -1);
    return NULL;
  }

  ssl = SSL_new(ctx);
  if (ssl == NULL) {
    SslErr(__FILE__, __LINE__, __errno(), "SSL_new");
    return NULL;
  }

  if (!SSL_set_fd(ssl, fd)) {
    SslErr(__FILE__, __LINE__, __errno(), "SSL_set_fd");
    return NULL;
  }

  SSL_set_accept_state(ssl);

  do {
    err = SSL_accept(ssl);
  } while (SslCheck(ssl, err) == 1);

  if (err != 1) {
    SslErr(__FILE__, __LINE__, __errno(), "SSL_accept");
    return NULL;
  }

  return ssl;
}

int AsyncSSLListen(void* pSocket) { return 0; }

// TODO not support UDP
int SSLListen(void* pSocket) {
  ssl_channel* sslSocket = pSocket;
  channel_extend* socket = sslSocket->psock;
  int err;
  fd_set fds;
  int nfds, maxfd = 0;
  int used = 1, next;
  SOCKET cfd, fd[MAX_CONNECT];
  SSL *cssl, *ssl[MAX_CONNECT];
  struct timeval tvTimeOut;
  sockaddr_info cliAddr;

  memset(ssl, 0x00, sizeof(ssl));
  fd[0] = socket->fd;
  ssl[0] = (SSL*)-1;
  while (socket->state == _CS_IDLE) {
    next = used;
    maxfd = 0;
    FD_ZERO(&fds);
    for (int i = 0, j = 0; i < MAX_CONNECT && j < used; i++) {
      if (ssl[i] != NULL) {
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
        if (socket->noblock != 1 || (cfd != EAGAIN && cfd != EWOULDBLOCK)) {
          ERROUT("accept", __errno());
        }
        continue;
      }

      int del = 0;
      do {
        cssl = NULL;
        if (socket->noblock == 1) {
          u_long option = 1;
#ifndef _WIN32
          if (ioctl(cfd, FIONBIO, &option))
#else
          if (ioctlsocket(cfd, FIONBIO, &option))
#endif
          {
            ERROUT("ioctl", __errno());
            del = 1;
            break;
          }
        }

        cssl = SSLAccept(cfd, sslSocket->ctx);
        if (cssl == NULL) {
          del = 1;
          break;
        }

        if (used >= MAX_CONNECT) {
          WARNING("accept when socket queue is full");
          del = 1;
          break;
        }

        err = SSLCallBack(cssl, cfd, socket->pRecv, socket->pSend,
                          socket->noblock, 1);
        if (err != 0) {
          del = 1;
          break;
        }
      } while (0);

      if (del) {
        SSL_Close(cssl, cfd);
        continue;
      }

      fd[next] = cfd;
      ssl[next] = cssl;
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
        err = SSLCallBack(ssl[i], fd[i], socket->pRecv, socket->pSend,
                          socket->noblock, 0);
        if (err != 0) {
          SSL_Close(ssl[i], fd[i]);
          ssl[i] = NULL;
          used--;
        }
      }
    }
  }

  for (int i = 1, j = 1; i < MAX_CONNECT && j < used; i++) {
    if (ssl[i] != NULL) {
      SSL_Close(ssl[i], fd[i]);
      ssl[i] = NULL;
      fd[i] = INVALID_SOCKET;
      j++;
    }
  }

  socket->state = _CS_END;
  return 0;
}

int SSLCallBack(SSL* ssl, SOCKET fd, RecvCallback pRecv, SendCallback pSend,
                int noblock, int init) {
  int err;
  int size;
#define MSGBUF_8K (1024 * 8)
  char sbuf[MSGBUF_8K];

  if (!init) {
    do {
      size = SSL_read(ssl, sbuf, MSGBUF_8K);
      if (size <= 0) {
        switch (SslCheck(ssl, size)) {
          case 1:
            if (noblock) continue;
          case 0:
            return 1;
          default:
            SslErr(__FILE__, __LINE__, __errno(), "SSL_read");
            return -1;
        }
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
      err = SSL_write(ssl, sbuf, size);
      if (err <= 0) {
        switch (SslCheck(ssl, err)) {
          case -1:
            SslErr(__FILE__, __LINE__, __errno(), "SSL_write");
            return -1;
          case 0:
            return 1;
        }
      }
    } while (err <= 0);
  } while (MSGBUF_8K <= size);

  return 0;
}

int UDPSSLListen(void* pSocket) {
  ssl_channel* sslSocket = pSocket;
  channel_extend* socket = pSocket;
  int err;
  fd_set fds;
  int nfds, maxfd;
  int used = 1, next;
  SOCKET cfd, fd[MAX_CONNECT];
  struct timeval tvTimeOut;
  sockaddr_info cliAddr;
  char sbuf[MSGBUF_8K];
  int size = 0;
  int slen = 0;

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
      slen = sizeof(cliAddr);
      size = recvfrom(socket->fd, sbuf, MSGBUF_8K, 0,
                      (struct sockaddr*)&cliAddr, &slen);
      unlock(&socket->mutex);
      if (size < 0) {
        err = __errno();
        if (socket->noblock != 1 || (err != EAGAIN && err != EWOULDBLOCK)) {
          ERROUT("recvfrom", err);
        }
        continue;
      }

      if (used >= MAX_CONNECT) {
        WARNING("accept when socket queue is full");
        err = sendto(socket->fd, FULLRPSMSG, sizeof(FULLRPSMSG), 0,
                     (struct sockaddr*)&cliAddr, slen);
        if (err < 0) {
          ERROUT("send", err);
        }
        continue;
      }

      cfd = UDPSocket(&socket->svraddr, &cliAddr);
      if (cfd < 0) {
        WARNING("create socket failed");
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

      err = socket->pRecv(cfd, 0, sbuf, size);
      if (err < 0) {
        continue;
      }

      do {
        size = socket->pSend(cfd, 0, sbuf, MSGBUF_8K);
        if (size <= 0) {
          err = size;
          break;
        }

        do {
          err = send(cfd, sbuf, size, 0);
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

      if (err < 0) {
        Close(cfd);
        continue;
      }
      fd[next] = cfd;
      used++;
    }
    if (socket->mutex == LOCK) {
      unlock(&socket->mutex);
    }

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

SSL* NewSSL(sockaddr_info* cliAddr) {}

#ifndef _SOCKET_SERVER
#define _SOCKET_SERVER
#endif
#include "../thread/lock.h"
#include "../thread/pool.h"
#include "socket.h"

static unsigned int lock_socket = FREE;

int __do_select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds,
                int timeout) {
  struct timeval tvTimeOut;
  tvTimeOut.tv_sec = timeout;
  tvTimeOut.tv_usec = 0;
  nfds = select(nfds, readfds, writefds, exceptfds, &tvTimeOut);
  if (nfds == 0) {
    return 0;
  } else if (nfds < 0) {
    ERROUT("select", __errno());
    return SELECT_ERR;
  }
}

int __bio_write(socket_base* socket, char* buf, int length) {
  fd_set fds;
  int err;
  int nfds;
  int totalSize = 0;

  if (socket->fd == INVALID_SOCKET) {
    return -1;
  }

  do {
    FD_ZERO(&fds);
    FD_SET(socket->fd, &fds);
#ifdef _WIN32
    nfds = __do_select(1, NULL, &fds, NULL, socket->opt.timeout);
#else
    nfds = __do_select(socket->fd + 1, NULL, &fds, NULL, socket->opt.timeout);
#endif
    if (nfds <= 0) {
      return nfds;
    }

    if (FD_ISSET(socket->fd, &fds)) {
      if (socket->ssl_st->p_flg == 2) {
        totalSize = SSL_write(socket->ssl_st->ssl, buf, length);
        if (__sslChk(socket->ssl_st->ssl, totalSize) < 0) {
          err = __errno();
          ERROUT("SSL_write", err);
#ifdef _WIN32
          if (err == WSAECONNRESET) return SOCKET_CLOSE;
#else
          if (err == EPIPE) return SOCKET_DOWN;
#endif
          return IO_ERR;
        }
      } else {
        totalSize = send(socket->fd, buf, length, 0);
        if (totalSize < 0) {
          err = __errno();
          ERROUT("send", err);
#ifdef _WIN32
          if (err == WSAECONNRESET) return SOCKET_CLOSE;
          if (err == WSAECONNABORTED) return SOCKET_DOWN;
#else
          if (err == ECONNRESET) return SOCKET_CLOSE;
          if (err == EPIPE) return SOCKET_DOWN;
#endif
          return IO_ERR;
        }
      }
    }
  } while (totalSize == 0);
  socket->state = _CS_REQ_SENT;
  return totalSize;
}

int __bio_read(socket_base* socket, char* buf, int length) {
  fd_set fds;
  int err;
  int nfds;
  int totalSize = 0;

  if (socket->fd == INVALID_SOCKET) {
    return STATE_ERR;
  }

  do {
    FD_ZERO(&fds);
    FD_SET(socket->fd, &fds);
#ifdef _WIN32
    nfds = __do_select(1, NULL, &fds, NULL, socket->opt.timeout);
#else
    nfds = __do_select(socket->fd + 1, NULL, &fds, NULL, socket->opt.timeout);
#endif
    if (nfds <= 0) {
      return nfds;
    }

    if (FD_ISSET(socket->fd, &fds)) {
      if (socket->ssl_st->p_flg == 2) {
        totalSize = SSL_read(socket->ssl_st->ssl, buf, length);
        if (__sslChk(socket->ssl_st->ssl, totalSize) < 0) {
          err = __errno();
          ERROUT("SSL_read", err);
#ifdef _WIN32
          if (err == WSAECONNRESET) return SOCKET_CLOSE;
#else
          if (err == 0) return SOCKET_CLOSE;
#endif
          return SSL_ERR;
        }
      } else {
        totalSize = recv(socket->fd, buf, length, 0);
        if (totalSize < 0) {
          err = __errno();
          ERROUT("recv", err);
#ifdef _WIN32
          if (err == WSAECONNRESET) return SOCKET_CLOSE;
          if (err == WSAECONNABORTED) return SOCKET_DOWN;
#endif
          return IO_ERR;
        } else if (totalSize == 0) {
          return SOCKET_CLOSE;
        }
      }
    }
  } while (totalSize == 0);
  socket->state = _CS_REQ_RECV;
  return totalSize;
}

typedef struct {
  socket_function* owner;
  int group;
  int final;
} paramter;

int __bio_listen(socket_function* owner) {
  int err;
  fd_set fds;
  int nfds, sFind;
  SSL* cssl;
  SOCKET cfd;
  struct sockaddr_in cliAddr;
  socket_base* mSocket = 0;
  paramter para[CT_NUM];
  thrd_t threads[CT_NUM] = {0};

  mSocket = owner->mSocket;

  if (mSocket->fd == INVALID_SOCKET) {
    if ((err = __bind(owner)) != 0) return -1;
  }

NEXT:
  while (mSocket->state == _CS_LISTEN) {
    FD_ZERO(&fds);
    FD_SET(mSocket->fd, &fds);
    nfds = __do_select(mSocket->fd + 1, &fds, NULL, NULL, mSocket->opt.timeout);
    if (nfds <= 0) {
      continue;
    }

    if (FD_ISSET(mSocket->fd, &fds)) {
      err = sizeof(cliAddr);
      cfd = accept(mSocket->fd, (PSOCKADDR)&cliAddr, &err);
      if (cfd < 0) {
        ERROUT("accept", __errno());
        continue;
      }

      sFind = -1;
      for (int i = 0; i < CT_NUM; i++) {
        if (mSocket->client[i].use < MAX_CONNECT) {
          for (int j = 0; j < MAX_CONNECT; j++) {
            if (mSocket->client[i].cfd[j] == INVALID_SOCKET) {
              if (mSocket->opt.ssl_flg != 0) {
                cssl = __ssl_bind(owner, cfd);
                if (cssl < 0) {
                  ERROUT("SSL_bind", __errno());
                  goto NEXT;
                }
                lock(&lock_socket);
                mSocket->ssl_st->fds[i].ssl[j] = cssl;
                mSocket->ssl_st->fds[i].p_flg[j] = 2;
                unlock(&lock_socket);

                if (owner->heloMsg) {
                Retry_SSL:
                  err = SSL_write(mSocket->ssl_st->fds[i].ssl[j],
                                  owner->heloMsg, strlen(owner->heloMsg));
                  if (err <= 0) {
                    switch (__sslChk(mSocket->ssl_st->fds[i].ssl[j], err)) {
                      case -1:
                      case 0:
                        ERROUT("SSL_write", __errno());
                        __close(owner, i, j);
                        goto NEXT;
                      case 1:
                        goto Retry_SSL;
                    }
                  }
                }
              } else {
                if (owner->heloMsg) {
                Retry:
                  err = send(cfd, owner->heloMsg, strlen(owner->heloMsg), 0);
                  if (err < 0) {
                    err = __errno();
                    if (err == EINTR) goto Retry;
                    ERROUT("send", err);
                    __close(owner, i, j);
                    goto NEXT;
                  };
                }
              }
              lock(&lock_socket);
              mSocket->client[i].cfd[j] = cfd;
              mSocket->client[i].use++;
              unlock(&lock_socket);
              sFind = i;
              goto Find;
            }
          }
        }
      }
    Find:
      if (sFind == -1) {
        WARNING("accept when socket queue is full");
#ifndef _WIN32
        close(cfd);
#else
        closesocket(cfd);
#endif
        continue;
      }

      if (threads[sFind] == 0) {
        para[sFind].group = sFind;
        para[sFind].owner = owner;
        para[sFind].final = 0;
#ifndef _WIN32
        if (pthread_create(&threads[sFind], NULL, __bio_commucation,
                           (void*)&para[sFind]) != 0)
#else
        if ((threads[sFind] = _beginthreadex(NULL, 0, __bio_commucation,
                                             (void*)&para[sFind], 0, 0)) == 0)
#endif
        {
          ERROUT("pthread_create", __errno());
          continue;
        }
      }
    }
  }

  return 0;
}

typedef struct {
  socket_function* owner;
  int group, idx;
} SocketParamter;

#ifndef _WIN32
u_int __bio_commucation(void* params)
#else
u_int __stdcall __bio_commucation(void* params)
#endif
{
  int err;
  fd_set fds;
  int nfds, sFind, nread;
  SOCKET max_fd = 0;
  socket_base* mSocket = 0;
  struct thread_pool* pool;
  paramter* para;
  SocketParamter* sockpara;
  char buf[8];

  para = params;
  mSocket = para->owner->mSocket;

  if ((err = createPool(&pool, 0, 0)) != 0) {
    ERROUT("createPool", err);
    return 0;
  }

  while (!para->final) {
    if (mSocket->client[para->group].use == 0) continue;
    FD_ZERO(&fds);
    for (int i = 0, j = 0;
         i < MAX_CONNECT && j < mSocket->client[para->group].use; i++) {
      if (mSocket->client[para->group].cfd[i] != INVALID_SOCKET) {
        FD_SET(mSocket->client[para->group].cfd[i], &fds);
        if (mSocket->client[para->group].cfd[i] > max_fd) {
          max_fd = mSocket->client[para->group].cfd[i];
        }
        j++;
      }
    }

    nfds = __do_select(max_fd + 1, &fds, NULL, NULL, mSocket->opt.timeout);
    if (nfds <= 0) {
      continue;
    }

    for (int i = 0, j = 0; i < MAX_CONNECT && j < nfds; i++) {
      if (mSocket->client[para->group].cfd[i] == INVALID_SOCKET ||
          !FD_ISSET(mSocket->client[para->group].cfd[i], &fds)) {
        continue;
      }
      j++;
      lock(&lock_socket);
      err = mSocket->client[para->group].flg[i] == 1;
      unlock(&lock_socket);
      if (err) {
        continue;
      }

      if (mSocket->ssl_st->p_flg == 1 &&
          mSocket->ssl_st->fds[para->group].p_flg[i] == 2) {
      Retry:
        err = SSL_peek(mSocket->ssl_st->fds[para->group].ssl[i], buf,
                       sizeof(buf));
        if (err <= 0) {
          switch (__sslChk(mSocket->ssl_st->fds[para->group].ssl[i], err)) {
            case 1:
              goto Retry;
            case 0:
              if (err == 0) goto Close;
            default:
              err = __errno();
              ERROUT("SSL_peek", err);
#ifdef _WIN32
              if (err == WSAECONNRESET) goto Close;
#else
              if (err == 0) goto Close;
              if (err == ECONNRESET) {
                SSL_free(mSocket->ssl_st->fds[para->group].ssl[i]);
                mSocket->ssl_st->fds[para->group].ssl[i] = 0x00;
                mSocket->ssl_st->fds[para->group].p_flg[i] = 1;
                goto Close;
              }
#endif
              continue;
              break;
          }
        }
      } else {
        err = recv(mSocket->client[para->group].cfd[i], buf, sizeof(buf),
                   MSG_PEEK);
        if (err == 0) {
        Close:
          lock(&lock_socket);
          __close(para->owner, para->group, i);
          unlock(&lock_socket);
          continue;
        } else if (err < 0) {
          err = __errno();
          ERROUT("recv", err);
#ifdef _WIN32
          if (err == WSAECONNABORTED) goto Close;
          if (err == WSAECONNRESET) goto Close;
#else
          if (err == ECONNRESET) goto Close;
#endif
        }
      }
      mSocket->client[para->group].flg[i] = 1;
      sockpara = (SocketParamter*)malloc(sizeof(SocketParamter));
      sockpara->group = para->group;
      sockpara->idx = i;
      sockpara->owner = para->owner;
      err = addTaskPool(pool, __bio_sub_commucation, sockpara, 0);
      if (err < 0) {
        ERROUT("addTaskPool", err);
        continue;
      }
    }
  }
  return 0;
}

int __bio_sub_commucation(int* final, void* params) {
  SOCKET fd = 0;
  SSL* ssl = 0;
  SocketParamter* para;
  para = params;
  fd = para->owner->mSocket->client[para->group].cfd[para->idx];
  ssl = para->owner->mSocket->ssl_st->fds
            ? para->owner->mSocket->ssl_st->fds[para->group].ssl[para->idx]
            : 0;
  ssl = para->owner->callback(para->owner, fd, ssl);
  if (ssl) {
    para->owner->mSocket->ssl_st->fds[para->group].ssl[para->idx] = ssl;
    para->owner->mSocket->ssl_st->fds[para->group].p_flg[para->idx] = 2;
  }
  lock(&lock_socket);
  para->owner->mSocket->client[para->group].flg[para->idx] = 0;
  unlock(&lock_socket);
  free(params);
  return 0;
}

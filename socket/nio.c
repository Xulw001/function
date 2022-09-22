#ifndef _SOCKET_SERVER
#define _SOCKET_SERVER
#endif
#include "socket.h"
#include "../thread/lock.h"
#include "../thread/pool.h"

typedef struct {
  socket_function* owner;
  int group;
  int final;
} paramter;

int __nio_listen(socket_function* owner) {
  int err;
  fd_set fds;
  int nfds, sFind, option;
  SSL* cssl;
  SOCKET cfd;
  struct timeval tvTimeOut;
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
    tvTimeOut.tv_sec = 0;
    tvTimeOut.tv_usec = 0;
    nfds = select(mSocket->fd + 1, &fds, NULL, NULL, &tvTimeOut);
    if (nfds == 0) {
      continue;
    } else if (nfds < 0) {
      ERROUT("select", __errno());
      return SELECT_ERR;
    }

    if (FD_ISSET(mSocket->fd, &fds)) {
      err = sizeof(cliAddr);
      cfd = accept(mSocket->fd, (PSOCKADDR)&cliAddr, &err);
      if (cfd < 0) {
        if (cfd != EAGAIN && cfd != EWOULDBLOCK) ERROUT("accept", __errno());
        continue;
      }

      sFind = -1;
      for (int i = 0; i < CT_NUM; i++) {
        if (mSocket->client[i].use < MAX_CONNECT) {
          for (int j = 0; j < MAX_CONNECT; j++) {
            if (mSocket->client[i].st[j].fd == INVALID_SOCKET) {
              option = 1;
#ifndef _WIN32
              if (ioctl(cfd, FIONBIO, &option))
#else
              if (ioctlsocket(cfd, FIONBIO, &option))
#endif
              {
                ERROUT("ioctl", __errno());
                __close(owner, i, j);
                goto NEXT;
              }

              if (mSocket->opt.ssl_flg != 0) {
                cssl = __ssl_bind(owner, cfd);
                if (cssl == 0) {
                  ERROUT("SSL_bind", __errno());
                  __close(owner, i, j);
                  goto NEXT;
                }
                lock(&mSocket->client[i].st[j].tasklock);
                mSocket->ssl_st->fds[i].ssl[j] = cssl;
                mSocket->ssl_st->fds[i].p_flg[j] = 2;
                unlock(&mSocket->client[i].st[j].tasklock);

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
                    if (err == EINTR || err == EAGAIN || err == EWOULDBLOCK)
                      goto Retry;
                    ERROUT("send", err);
                    __close(owner, i, j);
                    goto NEXT;
                  };
                }
              }
              lock(&mSocket->client[i].st[j].tasklock);
              mSocket->client[i].st[j].fd = cfd;
              mSocket->client[i].st[j].shutdown = 0;
              mSocket->client[i].st[j].tasknum = 0;
              mSocket->client[i].use++;
              unlock(&mSocket->client[i].st[j].tasklock);
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
        if (pthread_create(&threads[sFind], NULL, __nio_commucation,
                           (void*)&para[sFind]) != 0)
#else
        if ((threads[sFind] = _beginthreadex(NULL, 0, __nio_commucation,
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
u_int __nio_commucation(void* params)
#else
u_int __stdcall __nio_commucation(void* params)
#endif
{
  int err;
  fd_set fds;
  int nfds, sFind, nread;
  SOCKET max_fd = 0;
  socket_base* mSocket = 0;
  struct timeval tvTimeOut;
  struct thread_pool* pool;
  paramter* para;
  SocketParamter* sockpara;

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
      if (mSocket->client[para->group].st[i].fd != INVALID_SOCKET) {
        FD_SET(mSocket->client[para->group].st[i].fd, &fds);
        if (mSocket->client[para->group].st[i].fd > max_fd) {
          max_fd = mSocket->client[para->group].st[i].fd;
        }
        j++;
      }
    }

    tvTimeOut.tv_sec = 0;
    tvTimeOut.tv_usec = 0;
    nfds = select(max_fd + 1, &fds, NULL, NULL, &tvTimeOut);
    if (nfds <= 0) {
      continue;
    }

    for (int i = 0, j = 0; i < MAX_CONNECT && j < nfds; i++) {
      if (mSocket->client[para->group].st[i].fd == INVALID_SOCKET ||
          !FD_ISSET(mSocket->client[para->group].st[i].fd, &fds)) {
        continue;
      }
      j++;

#ifdef _WIN32
      if (_InterlockedCompareExchange(
              (unsigned long*)&mSocket->client[para->group].st[i].tasknum, 2,
              2) == 2)
#else
      if (__sync_bool_compare_and_swap(
              &mSocket->client[para->group].st[i].tasknum, 2, 2) == 1)
#endif
      {
        continue;
      }
#ifdef _WIN32
      _InterlockedIncrement(
          (unsigned long*)&mSocket->client[para->group].st[i].tasknum);
#else
      __sync_fetch_and_add(&mSocket->client[para->group].st[i].tasknum, 1);
#endif

      sockpara = (SocketParamter*)malloc(sizeof(SocketParamter));
      sockpara->group = para->group;
      sockpara->idx = i;
      sockpara->owner = para->owner;
      err = addTaskPool(pool, __nio_sub_commucation, sockpara, 0);
      if (err < 0) {
        ERROUT("addTaskPool", err);
        continue;
      }
    }
  }
  return 0;
}

int __nio_sub_commucation(int* final, void* params) {
  int err = 0;
  SSL* ssl = 0;
  SOCKET fd = 0;
  char buf[4] = {0};
  socket_base* mSocket;
  SocketParamter* para;
  para = params;
  mSocket = para->owner->mSocket;
  fd = mSocket->client[para->group].st[para->idx].fd;

  lock(&mSocket->client[para->group].st[para->idx].tasklock);

  if (mSocket->client[para->group].st[para->idx].shutdown == 1) {
    goto END;
  }

#ifndef _WIN32
  signal(SIGPIPE, SIG_IGN);
#endif

  while (1) {
    if (mSocket->ssl_st->p_flg == 1 &&
        mSocket->ssl_st->fds[para->group].p_flg[para->idx] == 2) {
      ssl = mSocket->ssl_st->fds[para->group].ssl[para->idx];
      err = SSL_peek(ssl, buf, sizeof(buf));
      if (err <= 0) {
        switch (__sslChk(ssl, err)) {
          case 1:
            goto END;
          case 0:
            if (err == 0) goto Close;
          default:
            __sslErr(__FILE__, __LINE__, __errno(), "SSL_peek");
            goto Close;
        }
      }
    } else {
      fd = mSocket->client[para->group].st[para->idx].fd;
      err = recv(fd, buf, sizeof(buf), MSG_PEEK);
      if (err == 0) {
      Close:
        __close(para->owner, para->group, para->idx);
        mSocket->client[para->group].st[para->idx].shutdown = 1;
        break;
      } else if (err < 0) {
        err = __errno();
#ifdef _WIN32
        if (err == WSAEWOULDBLOCK) break;
#else
        if (err == EAGAIN || err == EWOULDBLOCK) break;
#endif
        ERROUT("recv", err);
        goto Close;
      }
    }

    ssl = para->owner->callback(para->owner, fd, ssl);
    if (ssl) {
      para->owner->mSocket->ssl_st->fds[para->group].ssl[para->idx] = ssl;
      para->owner->mSocket->ssl_st->fds[para->group].p_flg[para->idx] = 2;
    }
  }

END:
  unlock(&mSocket->client[para->group].st[para->idx].tasklock);
#ifdef _WIN32
  _InterlockedDecrement(
      (unsigned long*)&mSocket->client[para->group].st[para->idx].tasknum);
#else
  __sync_fetch_and_sub(&mSocket->client[para->group].st[para->idx].tasknum, 1);
#endif

  free(params);
  return 0;
}

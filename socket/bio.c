#ifndef _SOCKET_SERVER
#define _SOCKET_SERVER
#endif
#include "socket.h"
#include "../thread/pool.h"
#include "../thread/lock.h"

static unsigned int lock_socket = FREE;

int __bio_write(socket_base* socket, const char* buf, int length) {
  fd_set fds;
  int nfds;
  int size, totalSize = 0;
  struct timeval tvTimeOut;

  if (socket->fd == INVALID_SOCKET) {
    return -1;
  }

  while (totalSize < length) {
    tvTimeOut.tv_sec = socket->opt.timeout;
    tvTimeOut.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(socket->fd, &fds);
#ifdef _WIN32
    nfds = select(1, NULL, &fds, NULL, &tvTimeOut);
#else
    nfds = select(socket->fd + 1, NULL, &fds, NULL, &tvTimeOut);
#endif
    if (nfds == 0) {
      return 0;
    } else if (nfds < 0) {
      ERROUT("select", errno);
      return -1;
    }

    if (FD_ISSET(socket->fd, &fds)) {
      if (socket->opt.ssl_flg != 0 && socket->ssl_st->p_flg == 2) {
        size =
            SSL_write(socket->ssl_st->ssl, buf + totalSize, length - totalSize);
        switch (__sslChk(socket->ssl_st->ssl, size)) {
          case -1:
            ERROUT("SSL_write", errno);
            return -1;
          case 0:
            totalSize += size;
            break;
          case 1:
            break;
        }
      } else {
        size = send(socket->fd, buf + totalSize, length - totalSize, 0);
        if (size < 0) {
          ERROUT("send", errno);
          return -1;
        };
        totalSize += size;
      }
    }
  }
  socket->state = _CS_REQ_SENT;
  return totalSize;
}

int __bio_read(socket_base* socket, const char* buf, int length) {
  fd_set fds;
  int nfds;
  int totalSize, size;
  socket_buff* mBuf = 0;
  struct timeval tvTimeOut;

  if (socket->fd == INVALID_SOCKET) {
    return -1;
  }

  do {
    tvTimeOut.tv_sec = 0;
    tvTimeOut.tv_usec = socket->opt.timeout;
    FD_ZERO(&fds);
    FD_SET(socket->fd, &fds);

#ifdef _WIN32
    nfds = select(1, NULL, &fds, NULL, &tvTimeOut);
#else
    nfds = select(socket->fd + 1, NULL, &fds, NULL, &tvTimeOut);
#endif
    if (nfds == 0) {
      return 0;
    } else if (nfds < 0) {
      ERROUT("select", errno);
      return -1;
    }

    if (FD_ISSET(socket->fd, &fds)) {
      if (socket->opt.ssl_flg != 0 && socket->ssl_st->p_flg == 2) {
        size = SSL_read(socket->ssl_st->ssl, mBuf->p + totalSize,
                        length - totalSize);
        switch (__sslChk(socket->ssl_st->ssl, size)) {
          case -1:
            ERROUT("SSL_read", errno);
            return -1;
          case 0:
            totalSize += size;
            break;
          case 1:
            break;
        }
      } else {
        size = recv(socket->fd, mBuf->p + totalSize, length - totalSize, 0);
        if (size < 0) {
          if (size == EAGAIN) {
            break;
          } else {
            ERROUT("recv", errno);
            return -1;
          }
        }
        totalSize += size;
      }
    }
  } while (totalSize <= length);
  socket->state = _CS_REQ_RECV;
  return 0;
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
  SOCKET cfd;
  struct sockaddr_in cliAddr;
  socket_base* mSocket = 0;
  struct timeval tvTimeOut;
  paramter para[CT_NUM];
  thrd_t threads[CT_NUM];

  mSocket = owner->mSocket;

  if (mSocket->fd == INVALID_SOCKET) {
    if ((err = __bind(owner)) != 0) return -1;
  }

  while (mSocket->state == _CS_LISTEN) {
    tvTimeOut.tv_sec = 0;
    tvTimeOut.tv_usec = mSocket->opt.timeout;
    FD_ZERO(&fds);
    FD_SET(mSocket->fd, &fds);

    nfds = select(mSocket->fd + 1, &fds, NULL, NULL, &tvTimeOut);
    if (nfds == 0) {
      continue;
    } else if (nfds < 0) {
      WARNING("select");
      err = errno;
      break;
    }

    if (FD_ISSET(mSocket->fd, &fds)) {
      cfd = accept(mSocket->fd, (PSOCKADDR)&cliAddr, sizeof(cliAddr));
      if (cfd < 0) {
        WARNING("accept");
        break;
      }

      sFind = -1;
      for (int i = 0; i < CT_NUM; i++) {
        if (mSocket->client[i].use < MAX_CONNECT) {
          for (int j = 0; j < MAX_CONNECT; j++) {
            if (mSocket->client[i].cfd[j] == INVALID_SOCKET) {
              lock(&lock_socket);
              mSocket->client[i].cfd[j] = cfd;
              mSocket->client[i].use++;
              unlock(&lock_socket);
              sFind = i;

              err = owner->callbackstart(cfd, &cliAddr);
              if (err < 0) {
                ERROUT("start", errno);
                break;
              }

              if (mSocket->opt.ssl_flg != 0) {
                err = __ssl_bind(owner, j + 1 + MAX_CONNECT * i);
                if (err < 0) {
                  ERROUT("bind", errno);
                }
              }

              break;
            }
          }
        }
      }

      if (sFind == -1) {
        WARNING("accept when socket queue is full");
#ifndef _WIN32
        close(cfd);
#else
        closesocket(cfd);
#endif
        continue;
      }

      if (threads[sFind] != 0) {
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
          ERROUT("pthread_create", errno);
          continue;
        }
      }
    }
  }

  return 0;
}

typedef struct {
  socket_function* owner;
  SOCKET fd;
  int nread;
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
    tvTimeOut.tv_sec = 0;
    tvTimeOut.tv_usec = mSocket->opt.timeout;
    FD_ZERO(&fds);
    for (int i = 0; i < MAX_CONNECT; i++) {
      FD_SET(mSocket->client[para->group].cfd[i], &fds);
      if (mSocket->client[para->group].cfd[i] > max_fd) {
        max_fd = mSocket->client[para->group].cfd[i];
      }
    }

    nfds = select(max_fd + 1, &fds, NULL, NULL, &tvTimeOut);
    if (nfds == 0) {
      continue;
    } else if (nfds < 0) {
      WARNING("select");
      continue;
    }

    for (int i = 1; i < MAX_CONNECT; i++) {
      if (mSocket->client[para->group].cfd[i] == INVALID_SOCKET ||
          !FD_ISSET(mSocket->client[para->group].cfd[i], &fds)) {
        continue;
      }

#ifndef _WIN32
      err = ioctl(mSocket->client[para->group].cfd[i], FIONREAD, &nread);
#else
      err = ioctlsocket(mSocket->client[para->group].cfd[i], FIONREAD, &nread);
#endif
      if (err < 0) {
        ERROUT("ioctl", errno);
        continue;
      }

      if (nread == 0) {
#ifndef _WIN32
        close(mSocket->client[para->group].cfd[i]);
#else
        closesocket(mSocket->client[para->group].cfd[i]);
#endif
        lock(&lock_socket);
        mSocket->client[para->group].cfd[i] = INVALID_SOCKET;
        mSocket->client[para->group].use--;
        unlock(&lock_socket);
        continue;
      }

      sockpara = (SocketParamter*)malloc(sizeof(SocketParamter));
      sockpara->fd = mSocket->client[para->group].cfd[i];
      sockpara->nread = nread;
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
  SocketParamter* para;
  para = params;
  para->owner->callback(para->fd, para->nread);
  free(params);
  return 0;
}
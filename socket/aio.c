#include <sys/fork.h>

#include "socket.h"
#include "thread/pool.h"

typedef enum { OPEN, ADD, MOD, DEL };

struct socket_item {
  SSL* ssl;
  int fd;
  int status;
  struct socket_item* next;
};

typedef struct {
  struct epoll_event* ev;
  struct socket_item* item;
  int epoll_fd;
} event_fd;

typedef struct {
  socket_function* owner;
  int epoll_fd;
  int fd;
  void* resv;
} SocketParamter;

int __do_set_event(int epoll_fd, int fd, int flag, int oneshot) {
  int err;
  int option;
  struct epoll_event ev;
  ev.events = EPOLLIN | EPOLLET;
  if (oneshot) {
    ev.events = | EPOLLONESHOT;
  }
  switch (flag) {
    case ADD:
      option = 1;
#ifndef _WIN32
      if (ioctl(fd, FIONBIO, &option))
#else
      if (ioctlsocket(fd, FIONBIO, &option))
#endif
      {
        ERROUT("ioctl", __errno());
        return -1;
      }
    case OPEN:
      err = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
      break;
    case MOD:
      err = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
      break;
    case CLOSE:
      err = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &ev);
      break;
  }

  if (err < 0) {
    ERROUT("epoll_ctl", __errno());
    return -1;
  }

  return 0;
}

int __do_aio_commucation(int* final, void* params) {
  int err = 0;
  //   int option;
  SSL* ssl = 0;
  //   char buf[4] = {0};
  socket_base* mSocket;
  SocketParamter* para;
  para = params;
  mSocket = para->owner->mSocket;
  //   fd = mSocket->cli_fd[para->group].st[para->idx].fd;

  //   lock(&mSocket->cli_fd[para->group].st[para->idx].tasklock);

  //   if (mSocket->cli_fd[para->group].st[para->idx].status == 2) {
  //     goto END;
  //   }

  //   if (mSocket->cli_fd[para->group].st[para->idx].status == 0) {
  //     fd = mSocket->cli_fd[para->group].st[para->idx].fd;

  if (mSocket->opt.ssl_flg != 0) {
    ssl = __ssl_bind(para->owner, para->fd);
    if (ssl == 0) {
      ERROUT("SSL_bind", __errno());
      goto Close;
    }
  }

Close:
  if (ssl != 0) {
    if (SSL_shutdown(ssl) != 1) {
      __sslErr(__FILE__, __LINE__, __errno(), "SSL_shutdown");
    }
    SSL_free(ssl);
  }
  if (para->fd != INVALID_SOCKET) {
    close(para->fd);
  }
  //       mSocket->ssl_st->fds[para->group].ssl[para->idx] = ssl;
  //       mSocket->ssl_st->fds[para->group].p_flg[para->idx] = 2;

  //       if (para->owner->heloMsg) {
  //       Retry_SSL:
  //         err =
  //             SSL_write(ssl, para->owner->heloMsg,
  //             strlen(para->owner->heloMsg));
  //         if (err <= 0) {
  //           switch (__sslChk(ssl, err)) {
  //             case -1:
  //             case 0:
  //               ERROUT("SSL_write", __errno());
  //               goto Close;
  //             case 1:
  //               goto Retry_SSL;
  //           }
  //         }
  //       }
  //     } else {
  //       if (para->owner->heloMsg) {
  //       Retry:
  //         err = send(fd, para->owner->heloMsg,
  //         strlen(para->owner->heloMsg), 0); if (err < 0) {
  //           err = __errno();
  //           if (err == EINTR || err == EAGAIN || err == EWOULDBLOCK) goto
  //           Retry; ERROUT("send", err); goto Close;
  //         };
  //       }
  //     }
  //     mSocket->cli_fd[para->group].st[para->idx].status = 1;
  //     goto END;
  //   }

  // #ifndef _WIN32
  //   signal(SIGPIPE, SIG_IGN);
  // #endif

  //   while (1) {
  //     if (mSocket->ssl_st->p_flg == 1 &&
  //         mSocket->ssl_st->fds[para->group].p_flg[para->idx] == 2) {
  //       ssl = mSocket->ssl_st->fds[para->group].ssl[para->idx];
  //       err = SSL_peek(ssl, buf, sizeof(buf));
  //       if (err <= 0) {
  //         switch (__sslChk(ssl, err)) {
  //           case 1:
  //             goto END;
  //           case 0:
  //             if (err == 0) goto Close;
  //           default:
  //             __sslErr(__FILE__, __LINE__, __errno(), "SSL_peek");
  //             goto Close;
  //         }
  //       }
  //     } else {
  //       fd = mSocket->cli_fd[para->group].st[para->idx].fd;
  //       err = recv(fd, buf, sizeof(buf), MSG_PEEK);
  //       if (err == 0) {
  //       Close:
  //         __close(para->owner, para->group, para->idx);
  //         mSocket->cli_fd[para->group].st[para->idx].status = 2;
  //         break;
  //       } else if (err < 0) {
  //         err = __errno();
  // #ifdef _WIN32
  //         if (err == WSAEWOULDBLOCK) break;
  // #else
  //         if (err == EAGAIN || err == EWOULDBLOCK) break;
  // #endif
  //         ERROUT("recv", err);
  //         goto Close;
  //       }
  //     }

  //     ssl = para->owner->callback(para->owner, fd, ssl);
  //     if (ssl) {
  //       para->owner->mSocket->ssl_st->fds[para->group].ssl[para->idx] =
  //       ssl;
  //       para->owner->mSocket->ssl_st->fds[para->group].p_flg[para->idx] =
  //       2;
  //     }
  //   }

  // END:
  //   unlock(&mSocket->cli_fd[para->group].st[para->idx].tasklock);
  // #ifdef _WIN32
  //   _InterlockedDecrement(
  //       (unsigned
  //       long*)&mSocket->cli_fd[para->group].st[para->idx].tasknum);
  // #else
  //   __sync_fetch_and_sub(&mSocket->cli_fd[para->group].st[para->idx].tasknum,
  //   1);
  // #endif

  free(params);
  return 0;
}

int __do_aio_accept(socket_function* owner) {
  int err;
  int nfds, cli;
  event_fd ev_fd;
  event_fd* pev_fd;
  SocketParamter* sockpara = 0;
  struct sockaddr_in cliAddr;

  pev_fd = &ev_fd;
  pev_fd->epoll_fd = epoll_create(MAX_CONNECT);
  if (pev_fd->epoll_fd < 0) {
    ERROUT("epoll_create", __errno());
    return EPOLL_ERR;
  }

  pev_fd->ev =
      (struct epoll_event*)malloc(sizeof(struct epoll_event) * MAX_CONNECT);
  if (pev_fd->ev == 0) {
    ERROUT("malloc", __errno());
    return MEMORY_ERR;
  }

  pev_fd->item =
      (struct socket_item*)malloc(sizeof(struct socket_item) * MAX_CONNECT);
  if (pev_fd->item < 0) {
    ERROUT("malloc", __errno());
    return EPOLL_ERR;
  }

  if (__do_set_event(pev_fd->epoll_fd, owner->mSocket->fd, OPEN, 0) < 0) {
    return EPOLL_ERR;
  }

  if ((err = createPool(&owner->pool, 0, 0)) != 0) {
    ERROUT("createPool", err);
    return POOL_ERR;
  }

  for (;;) {
    nfds = epoll_wait(pev_fd->epoll_fd, pev_fd->ev, MAX_CONNECT, 0);
    if (nfds < 0) {
      ERROUT("epoll_wait", __errno());
      return EPOLL_ERR;
    }
    for (int i = 0; i < nfds; i++) {
      if (pev_fd->ev[i].data.fd == owner->mSocket->fd) {
        err = sizeof(cliAddr);
        cli = accept(mSocket->fd, (PSOCKADDR)&cliAddr, &err);
        if (cli < 0) {
          if (cli != EAGAIN) ERROUT("accept", __errno());
          continue;
        }
        sockpara = (SocketParamter*)malloc(sizeof(SocketParamter));
        sockpara->owner = owner;
        sockpara->epoll_fd = pev_fd->epoll_fd;
        sockpara->fd = cli;
        sockpara->resv = 0;
      } else if (pev_fd->ev[i].events & EPOLLIN) {
        sockpara = (SocketParamter*)malloc(sizeof(SocketParamter));
        sockpara->owner = owner;
        sockpara->epoll_fd = pev_fd->epoll_fd;
        sockpara->fd = pev_fd->ev[i].data.fd;
        sockpara->resv = 0;
      } else {
        ;
      }
      if (sockpara) {
        err = addTaskPool(owner->pool, __do_aio_commucation, sockpara, 0);
        if (err < 0) {
          ERROUT("addTaskPool", err);
          continue;
        }
        sockpara = 0;
      }
    }
  }

  return 0;
}

int __do_fork(socket_function* owner) {
  int pid;
  pid = fork();
  if (pid < 0) {
    ERROUT("fork", __errno());
    return 0;
  } else if (pid > 0) {
    return pid;
  } else {
    exit(__do_aio_accept(owner));
  }
}

int __aio_accept(socket_function* owner) {
  int err, loop, idx;
  int pids[CT_NUM];
  socket_base* mSocket = 0;

  mSocket = owner->mSocket;

  if (mSocket->fd == INVALID_SOCKET) {
    if ((err = __bind(owner)) != 0) return err;
  }

  signal(SIGCHLD, SIG_IGN);

  for (loop = 0; loop < CT_NUM; loop++) {
    pids[loop] = __do_fork(owner);
    if (!pids[loop]) {
      loop--;
    }
  }

  while (mSocket->state == _CS_LISTEN) {
    pid = wait_pid(-1, &err, WUNTRACED);
    switch (pid) {
      case -1:
        ERROUT("fork", __errno());
        break;
      case 0:
        break;
      default:
        loop--;
        break;
    }
    for (idx = 0; idx < CT_NUM; idx++) {
      if (pids[idx] == pid) {
        break;
      }
    }

    while (loop < CT_NUM) {
      pids[idx] = __do_fork(owner);
      if (pids[idx] == 0) {
        continue;
      }
    }
  }

  return 0;
}
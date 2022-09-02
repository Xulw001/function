// #include <stdio.h>
// #include <stdlib.h>
// #include <unistd.h>

#ifndef _SOCKET_SERVER
#define _SOCKET_SERVER
#endif
#include "socket.h"
#include "../thread/pool.h"

socket_function* initServer(socket_option* opt, callback cb,
                            callbackstart start) {
  int buf = 0, err = 0;
  socket_function* fun = 0;
  socket_base* mSocket = 0;
  socket_ssl* ssl_st = 0;
  socket_fd* fds = 0;

  opt->timeout = opt->timeout ? opt->timeout : 30;

  if ((err = __optchk(opt)) < 0) {
    ERROUT("socket_option", err);
    return 0;
  }

  fun = (socket_function*)malloc(sizeof(socket_function));
  if (fun == 0) {
    ERROUT("malloc", __errno());
    return 0;
  }
  fun->mSocket = mSocket;
  fun->callback = cb;
  fun->callbackstart = start;
  fun->listen = __bio_listen;
  fun->close = __close;
  fun->fin = __fin;
  fun->send = __send;
  fun->recv = __recv;
  fun->load_cert_file = __load_cert_file;
  fun->ssl_listen = __ssl_listen;

  mSocket = (socket_base*)malloc(sizeof(socket_base));
  if (mSocket == 0) {
    ERROUT("malloc", __errno());
    return 0;
  }
  mSocket->opt = *opt;
  mSocket->fd = INVALID_SOCKET;
  mSocket->state = _CS_IDLE;
  mSocket->buf = NULL;
  mSocket->client = fds;
  mSocket->ssl_st = ssl_st;
  mSocket->opt.host = (char*)malloc(strlen(opt->host) + 1);
  memset(mSocket->opt.host, 0x00, strlen(opt->host) + 1);
  strcmp(mSocket->opt.host, opt->host);

  ssl_st = (socket_ssl*)malloc(sizeof(socket_ssl));
  if (ssl_st == 0) {
    ERROUT("malloc", __errno());
    return 0;
  }
  memset(ssl_st, 0x00, sizeof(socket_ssl));
  ssl_st->fds = 0;
  ssl_st->p_flg = 0;

  fds = (socket_fd*)malloc(sizeof(socket_fd) * CT_NUM);
  if (fds == 0) {
    ERROUT("malloc", __errno());
    return 0;
  }
  memset(ssl_st, 0x00, sizeof(socket_ssl));

  return fun;
}

int __bind(socket_function* owner) {
  int err = 0;
  int optlen, option;
  socket_option* opt;
  ADDRINFOT* pAI = NULL;
  ADDRINFOT hints;
  PSOCKADDR pSockAddr;
  socket_base* mSocket = NULL;
  char server[MAX_PATH];
  char chPort[6];

  memset(server, 0x00, sizeof(server));
  memset(chPort, 0x00, sizeof(chPort));
  memset(&hints, 0x00, sizeof(hints));
  pAI = NULL;
  mSocket = owner->mSocket;
  opt = &mSocket->opt;

  if (err = __open(owner) != 0) return err;

  if (mSocket->state != _CS_IDLE) {
    ERROUT("connect state", STATE_ERR);
    return STATE_ERR;
  }

  strncpy(server, opt->host, MAX_PATH);
  sprintf(chPort, "%d", opt->port);

  if (strcmp(server, "localhost") == 0)
    hints.ai_family = AF_INET;
  else
    hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if ((err = getaddrinfo(server, chPort, &hints, &pAI)) != 0) {
#ifdef _WIN32
    ERROUT("getaddrinfo", WSAGetLastError());
#else
    ERROUT("getaddrinfo", err);
#endif
    return BIND_ERR;
  }

  mSocket->fd = socket(pAI->ai_family, pAI->ai_socktype, pAI->ai_protocol);
  if (mSocket->fd == INVALID_SOCKET) {
    freeaddrinfo(pAI);
#ifdef _WIN32
    ERROUT("socket", WSAGetLastError());
#else
    ERROUT("socket", errno());
#endif
    return BIND_ERR;
  }

  optlen = sizeof(option);
  option = 1;
  if ((err = setsockopt(mSocket->fd, SOL_SOCKET, SO_REUSEADDR, &option,
                        optlen)) != 0) {
#ifdef _WIN32
    ERROUT("setsockopt", WSAGetLastError());
#else
    ERROUT("setsockopt", err);
#endif
    return BIND_ERR;
  }

  if (opt->nag_flg == 1) {
    optlen = sizeof(option);
    option = 1;
    if ((setsockopt(mSocket->fd, IPPROTO_TCP, TCP_NODELAY, &option, optlen)) !=
        0) {
#ifdef _WIN32
      ERROUT("setsockopt", WSAGetLastError());
#else
      ERROUT("setsockopt", err);
#endif
      return BIND_ERR;
    }
  }

  pSockAddr = (PSOCKADDR)pAI->ai_addr;
  switch (pAI->ai_family) {
    case AF_INET:
      if (((struct sockaddr_in*)pSockAddr)->sin_port == 0)
        ((struct sockaddr_in*)pSockAddr)->sin_port = htons((u_short)opt->port);
      break;
    case AF_INET6:
      if (((struct sockaddr_in6*)pSockAddr)->sin6_port == 0)
        ((struct sockaddr_in6*)pSockAddr)->sin6_port =
            htons((u_short)opt->port);
      break;
  }

  if (bind(mSocket->fd, (PSOCKADDR)pAI->ai_addr, pAI->ai_addrlen) < 0) {
    freeaddrinfo(pAI);
#ifdef _WIN32
    ERROUT("bind", WSAGetLastError());
#else
    ERROUT("bind", errno());
#endif
    return BIND_ERR;
  }

  if (listen(mSocket->fd, BACKLOG) < 0) {
    freeaddrinfo(pAI);
#ifdef _WIN32
    ERROUT("listen", WSAGetLastError());
#else
    ERROUT("listen", errno());
#endif
    return BIND_ERR;
  }

  if (opt->ssl_flg == 1) {
    if (owner->mSocket->ssl_st->p_flg == 0) {
      __load_cert_file(owner, 0, 0, 0, 0);
    }

    if ((err = __ssl_bind(owner, 0)) != 0) return err;
  }

  mSocket->state = _CS_LISTEN;
  return 0;
}

int __ssl_bind(socket_function* owner, int idx) {
  int i, j;
  SSL* fd;
  socket_ssl* ssl_st = owner->mSocket->ssl_st;

  if (owner->mSocket->opt.ssl_flg == 1) {
    if (ssl_st->p_flg == 0) {
      __load_cert_file(owner, 0, 0, 0, 0);
      ssl_st->p_flg = 1;
    }
  }

  if (ssl_st->p_flg != 2) {
    fd = SSL_new(ssl_st->ctx);
    if (fd == NULL) return __sslErr(__FILE__, __LINE__, "SSL_new");

    if (!SSL_set_fd(fd, owner->mSocket->fd))
      return __sslErr(__FILE__, __LINE__, "SSL_set_fd");

    SSL_set_accept_state(fd);
    SSL_set_tlsext_host_name(fd, owner->mSocket->opt.host);

    if (SSL_accept(fd) != 1) {
      return __sslErr(__FILE__, __LINE__, "SSL_connect");
    }

    ssl_st->ssl = fd;

    ssl_st->p_flg = 2;
  }

  if (idx-- != 0) {
    i = idx / MAX_CONNECT;
    j = idx % MAX_CONNECT;
    if (owner->mSocket->client[i].cfd[j] != INVALID_SOCKET) {
      fd = ssl_st->fds[i].ssl[j] = SSL_new(ssl_st->ctx);
      if (fd == NULL) return __sslErr(__FILE__, __LINE__, "SSL_new");

      if (!SSL_set_fd(fd, owner->mSocket->client[i].cfd[j]))
        return __sslErr(__FILE__, __LINE__, "SSL_set_fd");

      SSL_set_accept_state(fd);
      SSL_set_tlsext_host_name(fd, owner->mSocket->opt.host);

      if (SSL_accept(fd) != 1) {
        return __sslErr(__FILE__, __LINE__, "SSL_connect");
      }

      ssl_st->fds[i].ssl[j] = fd;
      ssl_st->fds[i].p_flg[j] = 2;
    }
  }

  return 0;
}

typedef struct {
  socket_function* owner;
  int group;
} paramter;

int __bio_listen(socket_function* owner) {
  int err;
  fd_set fds;
  int nfds, sFind;
  SOCKET cfd;
  struct sockaddr_in cliAddr;
  socket_base* mSocket = 0;
  struct timeval tvTimeOut;
  struct thread_pool* pool;
  paramter* para;

  mSocket = owner->mSocket;

  if (mSocket->fd == INVALID_SOCKET) {
    if ((err = __bind(owner)) != 0) return -1;
  }

  if ((err = createPool(&pool, 0, 0)) != 0) return -1;

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

      for (int i = 0; i < CT_NUM; i++) {
        if (mSocket->client[i].use < MAX_CONNECT) {
          for (int j = 0; j < MAX_CONNECT; j++) {
            if (mSocket->client[i].cfd[j] == INVALID_SOCKET) {
              para = (paramter*)malloc(sizeof(paramter));
              para->owner = owner;
              para->group = i;
              mSocket->client[i].cfd[j] = cfd;
              sFind = 1;

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

      if (!sFind) {
        WARNING("accept when socket queue is full");
#ifndef _WIN32
        close(cfd);
#else
        closesocket(cfd);
#endif
        continue;
      }

      addTaskPool(pool, __commucation, para, 1);
    }
  }

  return err;
}

int __commucation(int final, void* params) {
  int err;
  fd_set fds;
  int nfds, sFind, nread;
  SOCKET max_fd = 0;
  socket_base* mSocket = 0;
  struct timeval tvTimeOut;
  struct thread_pool* pool;
  paramter* para;

  para = params;
  mSocket = para->owner->mSocket;
  while (final) {
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
      err = errno;
      break;
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
#ifndef _WIN32
        close(mSocket->client[para->group].cfd[i]);
#else
        closesocket(mSocket->client[para->group].cfd[i]);
#endif
        break;
      }

      if (nread == 0) {
#ifndef _WIN32
        close(mSocket->client[para->group].cfd[i]);
#else
        closesocket(mSocket->client[para->group].cfd[i]);
#endif
        mSocket->client[para->group].cfd[i] = INVALID_SOCKET;
        break;
      }

      err = para->owner->callback(mSocket->client[para->group].cfd[i], nread);
      if (err < 0) {
        ERROUT("callback", errno);
#ifndef _WIN32
        close(mSocket->client[para->group].cfd[i]);
#else
        closesocket(mSocket->client[para->group].cfd[i]);
#endif
        mSocket->client[para->group].cfd[i] = INVALID_SOCKET;
        break;
      }
    }
  }
}

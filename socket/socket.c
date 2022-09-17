#include "socket.h"

int __optchk(socket_option* opt) {
  char flg = opt->udp_flg | opt->aio_flg | opt->cls_flg | opt->ssl_flg;
  if (flg < 0 || flg > 1) return OPT_ERR;

  if (opt->nag_flg < 0 || opt->nag_flg > 2) return OPT_ERR;

  if (opt->port < 0 || opt->port > 65536) return OPT_ERR;

  if (opt->host == 0 || opt->host[0] == '\0') return OPT_ERR;
  return 0;
}

int __open(socket_function* owner) {
#ifdef _WIN32
  WSADATA wsaData;
  WORD wVersion;
  wVersion = MAKEWORD(2, 2);
  if (WSAStartup(wVersion, &wsaData) != 0) {
    ERROUT("WSAStartup", __errno());
    return WAS_ERR;
  }

  if (wVersion != wsaData.wVersion) {
    WSACleanup();
    ERROUT("WSAStartup.wVersion", wVersion);
    return WAS_ERR;
  }
#endif

  if (owner->mSocket->opt.ssl_flg != 0) {
#ifdef _WIN32
    while (RAND_status() == 0)
      ;
#endif
    SSL_library_init();
    SSL_load_error_strings();
  }
  return 0;
}

int final(socket_function* fun) {
  int err = 0;
  if (fun == NULL) {
    return 0;
  }

  if (fun->mSocket == 0) {
    free(fun);
    return 0;
  }

  if ((err = __close(fun, -1, 0)) != 0) {
    return err;
  }

  if (fun->mSocket->buf != NULL) {
    free(fun->mSocket->buf);
    fun->mSocket->buf = NULL;
  }

  if (fun->mSocket->opt.host != NULL) {
    free(fun->mSocket->opt.host);
    fun->mSocket->opt.host = NULL;
  }

  free(fun->mSocket);
  fun->mSocket = NULL;

  return 0;
}

int __fin(socket_function* owner) {
  int err = 0;
  socket_buff* buff = 0;

  buff = owner->mSocket->buf;
  switch (owner->mSocket->state) {
    case _CS_REQ_SENT:
      err = __bio_write(owner->mSocket, buff->p + buff->r, buff->w - buff->r);
      if (err < 0) {
        return err;
      }
      break;
    case _CS_REQ_RECV:
      while ((err = __bio_read(owner->mSocket, buff->p, MSGBUF_32K)) != 0) {
        if (err < 0) {
          return err;
        } else if (err < MSGBUF_32K) {
          break;
        }
      }
      break;
  }
  owner->mSocket->buf->r = 0;
  owner->mSocket->buf->w = -1;
  return 0;
}

int __close(socket_function* owner, int group, int idx) {
  if (group == -1) {
    return __close0(owner);
  }
  if (owner->mSocket->ssl_st->fds != NULL) {
    if (owner->mSocket->ssl_st->fds[group].ssl[idx]) {
      if (SSL_shutdown(owner->mSocket->ssl_st->fds[group].ssl[idx]) != 1) {
        __sslErr(__FILE__, __LINE__, __errno(), "SSL_shutdown");
      }
      SSL_free(owner->mSocket->ssl_st->fds[group].ssl[idx]);
      owner->mSocket->ssl_st->fds[group].ssl[idx] = 0x00;
      owner->mSocket->ssl_st->fds[group].p_flg[idx] = 1;
    }
  }

  if (owner->mSocket->client != NULL) {
    if (owner->mSocket->client[group].st[idx].fd != INVALID_SOCKET) {
#ifndef _WIN32
      close(owner->mSocket->client[group].st[idx].fd);
#else
      closesocket(owner->mSocket->client[group].st[idx].fd);
#endif
      owner->mSocket->client[group].st[idx].fd = INVALID_SOCKET;
      owner->mSocket->client[group].use--;
    }
  }

  return 0;
}

int __close0(socket_function* owner) {
  if (owner->mSocket->state == _CS_IDLE) {
    WARNING("close when not connect");
    return 0;
  }

  if (owner->mSocket->ssl_st->ssl != NULL) {
    if (owner->mSocket->ssl_st->fds) {
      socket_ssl_fd* fd = owner->mSocket->ssl_st->fds;
      for (int i = 0; i < CT_NUM; i++) {
        for (int k = 0; k < MAX_CONNECT; k++) {
          if (fd[i].ssl[k]) {
            SSL_shutdown(fd[i].ssl[k]);
            SSL_free(fd[i].ssl[k]);
            fd[i].ssl[k] = 0x00;
          }
        };
      }
    }
    SSL_shutdown(owner->mSocket->ssl_st->ssl);
    SSL_free(owner->mSocket->ssl_st->ssl);
    owner->mSocket->ssl_st->ssl = 0;
  }

  if (owner->mSocket->ssl_st->ctx != NULL)
    SSL_CTX_free(owner->mSocket->ssl_st->ctx);

  if (owner->mSocket->client != NULL) {
    socket_fd* pfd = owner->mSocket->client;
    for (int i = 0; i < CT_NUM; i++) {
      if (pfd->use == 0) continue;
      for (int k = 0; k < MAX_CONNECT; k++) {
        if (pfd[i].st[k].fd) {
#ifndef _WIN32
          close(pfd[i].st[k].fd);
#else
          closesocket(pfd[i].st[k].fd);
#endif
          pfd[i].st[k].fd = INVALID_SOCKET;
        }
      }
    }
    owner->mSocket->client = 0x00;
  }

  if (owner->mSocket->fd != INVALID_SOCKET) {
#ifndef _WIN32
    close(owner->mSocket->fd);
#else
    closesocket(owner->mSocket->fd);
    WSACleanup();
#endif
    owner->mSocket->fd = INVALID_SOCKET;
  }
  owner->mSocket->state = _CS_IDLE;
  return 0;
}

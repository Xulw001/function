#include "socket.h"

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
          if (err == WSAECONNABORTED) return SOCKET_DOWN;
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
          if (err == WSAECONNABORTED) return SOCKET_DOWN;
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

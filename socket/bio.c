#include "socket.h"

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
        size = SSL_write(socket->ssl_st->ssl, buf + totalSize,
                         length - totalSize);
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

#include "ssl_client.h"

int SSLSendMsg(Socket* socket, char* buff, unsigned size) {
  int errRet = 0;
  if (buff == NULL || *buff == '\0') {
    return 0;
  }
  if (size <= 0) {
    return 0;
  }
  if (socket->fd == NULL) {
    errRet = InitSSLClient(socket);
    if (errRet) {
      return errRet;
    }
  }
  return SSLSend(socket->fd, buff, size);
}

int SSLRecvMsg(Socket* socket, char* buff, unsigned size) {
  int errRet = 0;
  if (buff == NULL) {
    return 0;
  }
  if (size <= 0) {
    return 0;
  }
  if (socket->fd == NULL) {
    errRet = InitSSLClient(socket);
    if (errRet) {
      return errRet;
    }
  }
  return SSLRecv(socket->fd, buff, size);
}

int InitSSLClient(Socket* pSocket) {
  int err = 0;
  ssl_channel* pssl = NULL;
  channel* psock = NULL;

  err = InitSSLSocket(pSocket, 1);
  if (err) {
    return err;
  }
  pssl = pSocket->fd;

  err = InitClient(pSocket);
  if (err) {
    return err;
  }
  psock = pSocket->fd;

  pssl->ssl = SSL_new(pssl->ctx);
  if (pssl->ssl == NULL)
    return SslErr(__FILE__, __LINE__, __errno(), "SSL_new");

  if (!SSL_set_fd(pssl->ssl, psock->fd))
    return SslErr(__FILE__, __LINE__, __errno(), "SSL_set_fd");

  SSL_set_connect_state(pssl->ssl);

  SSL_set_tlsext_host_name(pssl->ssl, pSocket->info.host);

  do {
    err = SSL_connect(pssl->ssl);
    if (err == 1) break;
    if (SslCheck(pssl->ssl, err) < 0) {
      return SslErr(__FILE__, __LINE__, __errno(), "SSL_connect");
    }
  } while (1);

  pssl->psock = psock;
  pSocket->fd = pssl;
  return 0;
}

int EndSSLClient(Socket* socket) {
  int err = 0;
  if (socket->fd != NULL) {
    ssl_channel* ssl = socket->fd;
    SOCKET fd = INVALID_SOCKET;
    if (ssl->psock != NULL) {
      fd = ((channel*)ssl->psock)->fd;
      free(ssl->psock);
      ssl->psock = NULL;
    }
    SSL_Close(ssl->ssl, fd);
    SSL_CTX_free(ssl->ctx);

    free(socket->fd);
    socket->fd = NULL;
  }
  return err;
}

int SSLSend(ssl_channel* socket, char* buff, unsigned size) {
  fd_set fds;
  int err;
  int nfds;
  int totalSize = 0;
  channel* psock = socket->psock;
  do {
    FD_ZERO(&fds);
    FD_SET(psock->fd, &fds);
#ifdef _WIN32
    nfds = Select(1, NULL, &fds, NULL, psock->timeout);
#else
    nfds = Select(psock->fd + 1, NULL, &fds, NULL, psock->timeout);
#endif
    if (nfds <= 0) {
      return nfds;
    }

    if (FD_ISSET(psock->fd, &fds)) {
      totalSize = SSL_write(socket->ssl, buff, size);
      if (SslCheck(socket->ssl, totalSize) < 0) {
        err = __errno();
        ERROUT("SSL_write", err);
#ifdef _WIN32
        if (err == WSAECONNRESET) return 0;
        if (err == WSAECONNABORTED) return 1;
#else
        if (err == EPIPE) return 1;
#endif
        return -1;
      }
    }
  } while (totalSize < 0);
  return totalSize;
}

int SSLRecv(ssl_channel* socket, char* buff, unsigned size) {
  fd_set fds;
  int err;
  int nfds;
  int totalSize = 0;
  channel* psock = socket->psock;

  do {
    FD_ZERO(&fds);
    FD_SET(psock->fd, &fds);
#ifdef _WIN32
    nfds = Select(1, NULL, &fds, NULL, psock->timeout);
#else
    nfds = Select(psock->fd + 1, NULL, &fds, NULL, psock->timeout);
#endif
    if (nfds <= 0) {
      return nfds;
    }

    if (FD_ISSET(psock->fd, &fds)) {
      totalSize = SSL_read(socket->ssl, buff, size);
      if (SslCheck(socket->ssl, totalSize) < 0) {
        err = __errno();
        ERROUT("send", err);
#ifdef _WIN32
        if (err == WSAECONNRESET) return 0;
        if (err == WSAECONNABORTED) return 1;
#else
        if (err == 0) return 1;
#endif
        return -1;
      }
      if (totalSize == 0) {
        return 0;
      }
    }
  } while (totalSize < 0);
  return totalSize;
}

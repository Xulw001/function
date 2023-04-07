#include "client.h"
#include <stdio.h>
#include "socket.h"

int SendMsg(Socket* socket, char* buff, unsigned size) {
  int errRet = 0;
  if (buff == NULL || *buff == '\0') {
    return 0;
  }
  if (size <= 0) {
    return 0;
  }
  if (socket->fd == NULL) {
    errRet = InitClient(socket);
    if (errRet) {
      return errRet;
    }
  }
  return Send(socket->fd, buff, size);
}

int RecvMsg(Socket* socket, char* buff, unsigned size) {
  int errRet = 0;
  if (buff == NULL) {
    return 0;
  }
  if (size <= 0) {
    return 0;
  }
  if (socket->fd == NULL) {
    errRet = InitClient(socket);
    if (errRet) {
      return errRet;
    }
  }
  return Recv(socket->fd, buff, size);
}

int InitClient(Socket* pSocket) {
  int err = 0;
  int optlen, option;
  channel* psock = NULL;
  ADDRINFOT* pAI = NULL;
  ADDRINFOT hints;
  PSOCKADDR pSockAddr;
  char server[HOST_NAME_MAX];
  char chPort[6];

  psock = (channel*)malloc(sizeof(channel));
  if (psock == 0) {
    ERROUT("malloc", __errno());
    return -1;
  }

  memset(chPort, 0x00, sizeof(chPort));
  memset(&hints, 0x00, sizeof(hints));
  strncpy(server, pSocket->info.host, HOST_NAME_MAX);
  sprintf(chPort, "%d", pSocket->info.port);

  if (strcmp(server, "localhost") == 0)
    hints.ai_family = AF_INET;
  else
    hints.ai_family = AF_UNSPEC;

  if (pSocket->opt.udp_flg) {
    hints.ai_socktype = SOCK_DGRAM;
  } else {
    hints.ai_socktype = SOCK_STREAM;
  }

  if ((err = getaddrinfo(server, chPort, &hints, &pAI)) != 0) {
    ERROUT("getaddrinfo", __errno());
    goto ERR;
  }

  psock->fd = socket(pAI->ai_family, pAI->ai_socktype, pAI->ai_protocol);
  if (psock->fd == INVALID_SOCKET) {
    ERROUT("socket", __errno());
    goto ERR;
  }

  if (connect(psock->fd, (PSOCKADDR)pAI->ai_addr, pAI->ai_addrlen) < 0) {
    ERROUT("socket", __errno());
    goto ERR;
  }

  if (pSocket->opt.nio_flg && pSocket->opt.ssl_flg) {
    option = 1;
#ifndef _WIN32
    if (ioctl(psock->fd, FIONBIO, &option))
#else
    if (ioctlsocket(psock->fd, FIONBIO, &option))
#endif
    {
      ERROUT("ioctl", __errno());
      goto ERR;
    }
  }

  psock->timeout = pSocket->info.timeout;
  pSocket->fd = psock;
  freeaddrinfo(pAI);
  return 0;
ERR:
  if (pAI != NULL) {
    freeaddrinfo(pAI);
    pAI = NULL;
  }
  if (psock != NULL) {
    free(psock);
    psock = NULL;
  }
  return -1;
}

int EndClient(Socket* socket) {
  int err = 0;
  if (socket->fd != NULL) {
    err = Close(((channel*)socket->fd)->fd);
    free(socket->fd);
    socket->fd = NULL;
  }
  return 0;
}

int Send(channel* socket, char* buff, unsigned size) {
  fd_set fds;
  int err;
  int nfds;
  int totalSize = 0;

  do {
    FD_ZERO(&fds);
    FD_SET(socket->fd, &fds);
#ifdef _WIN32
    nfds = Select(1, NULL, &fds, NULL, socket->timeout);
#else
    nfds = Select(socket->fd + 1, NULL, &fds, NULL, socket->timeout);
#endif
    if (nfds <= 0) {
      return nfds;
    }

    if (FD_ISSET(socket->fd, &fds)) {
      totalSize = send(socket->fd, buff, size, 0);
      if (totalSize < 0) {
        err = __errno();
        ERROUT("send", err);
#ifdef _WIN32
        if (err == WSAECONNRESET) return 0;
        if (err == WSAECONNABORTED) return 1;
#else
        if (err == ECONNRESET) return 0;
        if (err == EPIPE) return 1;
#endif
        return -1;
      }
    }
  } while (totalSize == 0);
  return totalSize;
}

int Recv(channel* socket, char* buff, unsigned size) {
  fd_set fds;
  int err;
  int nfds;
  int totalSize = 0;

  do {
    FD_ZERO(&fds);
    FD_SET(socket->fd, &fds);
#ifdef _WIN32
    nfds = Select(1, NULL, &fds, NULL, socket->timeout);
#else
    nfds = Select(socket->fd + 1, NULL, &fds, NULL, socket->timeout);
#endif
    if (nfds <= 0) {
      return nfds;
    }

    if (FD_ISSET(socket->fd, &fds)) {
      totalSize = recv(socket->fd, buff, size, 0);
      if (totalSize < 0) {
        err = __errno();
        ERROUT("recv", err);
#ifdef _WIN32
        if (err == WSAECONNRESET) return 0;
        if (err == WSAECONNABORTED) return 1;
#endif
        return -1;
      } else if (totalSize == 0) {
        return 0;
      }
    }
  } while (totalSize == 0);
  return totalSize;
}

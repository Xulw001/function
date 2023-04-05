#include "server.h"
#include "ssl_client.h"
#include "ssl_server.h"

int InitSocket(Socket* pSocket) {
#ifdef _WIN32
  WSADATA wsaData;
  WORD wVersion;
  wVersion = MAKEWORD(2, 2);
  if (WSAStartup(wVersion, &wsaData) != 0) {
    ERROUT("WSAStartup", __errno());
    return -1;
  }

  if (wVersion != wsaData.wVersion) {
    WSACleanup();
    ERROUT("WSAStartup.wVersion", wVersion);
    return -1;
  }
#endif
  return 0;
}

int SetSocketInfo(Socket* socket, const char* host, unsigned port,
                  unsigned timeout) {
  if (host == 0 || *host == '\0') {
    return -1;
  } else {
    strncpy(socket->info.host, host, sizeof(socket->info.host));
  }

  if (port < 0 || port > 65536) {
    return -1;
  } else {
    socket->info.port = port;
  }

  socket->info.timeout = timeout;

  socket->fd = NULL;

  return 0;
}

int SetSocketOption(Socket* socket, option opt, int val) {
  switch (opt) {
    case UDP:
      socket->opt.udp_flg = val;
      break;
    case NOBLOCK:
      socket->opt.nio_flg = val;
      break;
    case TLS:
      socket->opt.ssl_flg = val;
      break;
    case AIO:
      socket->opt.aio_flg = val;
      break;
    default:
      return -1;
  }
  return 0;
}

int SetSSLOption(Socket* socket, ssl_option opt, ...) {
  int err = 0;
  va_list va;
  va_start(va, opt);
  switch (opt) {
    case SSLVER: {
      socket->sslInfo.ver = va_arg(va, int);
      if (socket->sslInfo.ver < _SSLV23 || socket->sslInfo.ver > _DTLSV12) {
        err = -1;
      }
    } break;
    case VERIFY: {
      int opt = va_arg(va, int);
      socket->sslInfo.verify = opt & 0xf;
      socket->sslInfo.caopt = opt & 0xf0;
      if (socket->sslInfo.verify < _SSL_VER_NONE ||
          socket->sslInfo.verify > _SSL_VER_PEER_UPPER) {
        err = -1;
        break;
      }
      if (socket->sslInfo.caopt < _SSL_CA_NO ||
          socket->sslInfo.caopt > _SSL_CA_ALL) {
        err = -1;
        break;
      }

      if (_SSL_VER_NONE != socket->sslInfo.verify &&
          _SSL_CA_NO == socket->sslInfo.caopt) {
        err = -1;
        break;
      }

      char* filepath = NULL;
      switch (socket->sslInfo.caopt) {
        case _SSL_CA_PATH:
          filepath = va_arg(va, char*);
          if (NULL == filepath) {
            err = -1;
            break;
          }
          socket->sslInfo.cCAPath = (char*)malloc(strlen(filepath) + 1);
          strcpy(socket->sslInfo.cCAPath, filepath);
          break;
        case _SSL_CA_FILE:
          filepath = va_arg(va, char*);
          if (NULL == filepath) {
            err = -1;
            break;
          }
          socket->sslInfo.cCAFile = (char*)malloc(strlen(filepath) + 1);
          strcpy(socket->sslInfo.cCAFile, filepath);
          break;
        case _SSL_CA_ALL:
          filepath = va_arg(va, char*);
          if (NULL == filepath) {
            err = -1;
            break;
          }
          socket->sslInfo.cCAPath = (char*)malloc(strlen(filepath) + 1);
          strcpy(socket->sslInfo.cCAPath, filepath);
          filepath = va_arg(va, char*);
          if (NULL == filepath) {
            err = -1;
            break;
          }
          socket->sslInfo.cCAFile = (char*)malloc(strlen(filepath) + 1);
          strcpy(socket->sslInfo.cCAFile, filepath);
          break;
        default:
          break;
      }
    } break;
    case CERTFILE: {
      socket->sslInfo.filever = va_arg(va, int);
      if (socket->sslInfo.filever < PEM || socket->sslInfo.filever > ASN1) {
        err = -1;
      }

      char* filepath = NULL;
      filepath = va_arg(va, char*);
      if (NULL == filepath) {
        err = -1;
        break;
      }
      socket->sslInfo.certfile = (char*)malloc(strlen(filepath) + 1);
      strcpy(socket->sslInfo.certfile, filepath);

      filepath = va_arg(va, char*);
      if (NULL == filepath) {
        err = -1;
        break;
      }
      socket->sslInfo.keyfile = (char*)malloc(strlen(filepath) + 1);
      strcpy(socket->sslInfo.keyfile, filepath);

      filepath = va_arg(va, char*);
      if (filepath != NULL) {
        socket->sslInfo.keypass = (char*)malloc(strlen(filepath) + 1);
        strcpy(socket->sslInfo.keypass, filepath);
      }
    } break;
    case EXTEND: {
      SSL_EXTEND_OPT* pOpt = va_arg(va, SSL_EXTEND_OPT*);
      if (NULL == pOpt) {
        err = -1;
        break;
      }
      socket->sslInfo.opt = (SSL_EXTEND_OPT*)malloc(sizeof(SSL_EXTEND_OPT));
      memcpy(socket->sslInfo.opt, pOpt, sizeof(SSL_EXTEND_OPT));
    } break;
    default: {
      err = -1;
    } break;
  }
  va_end(va);
  return err;
}

int SocketSend(Socket* socket, char* buff, unsigned size) {
  if (socket->opt.ssl_flg) {
    return SSLSendMsg(socket, buff, size);
  } else {
    return SendMsg(socket, buff, size);
  }
}

int SocketRecv(Socket* socket, char* buff, unsigned size) {
  if (socket->opt.ssl_flg) {
    return SSLRecvMsg(socket, buff, size);
  } else {
    return RecvMsg(socket, buff, size);
  }
  return 0;
}

int SocketBind(Socket* socket, RecvCallback pRecv, SendCallback pSend) {
  if (socket->opt.udp_flg && socket->opt.ssl_flg) {
    return UDPSSLBind(socket, pRecv, pSend);
  } else if (socket->opt.udp_flg && !socket->opt.ssl_flg) {
    return UDPBind(socket, pRecv, pSend);
  } else if (!socket->opt.udp_flg && socket->opt.ssl_flg) {
    return SSLBind(socket, pRecv, pSend);
  } else if (!socket->opt.udp_flg && !socket->opt.ssl_flg) {
    return TCPBind(socket, pRecv, pSend);
  }
  return 0;
}

int EndSocket(Socket* socket) {
  if (socket->opt.resv2 == 0x01) {
    if (!socket->opt.ssl_flg) {
      return EndServer(socket);
    } else {
      return EndSSLServer(socket);
    }
  } else {
    if (!socket->opt.ssl_flg) {
      return EndClient(socket);
    } else {
      return EndSSLClient(socket);
    }
  }
}

int Select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds,
           int timeout) {
  struct timeval tvTimeOut;
  tvTimeOut.tv_sec = timeout;
  tvTimeOut.tv_usec = 0;
  nfds = select(nfds, readfds, writefds, exceptfds, &tvTimeOut);
  if (nfds == 0) {
    return 0;
  } else if (nfds < 0) {
    ERROUT("select", __errno());
    return -1;
  }
  return nfds;
}

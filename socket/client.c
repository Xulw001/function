#include "socket.h"

int __connect(socket_function* owner) {
  int err = 0;
  int optlen, option;
  socket_option* opt;
  ADDRINFOT* pAI = NULL;
  ADDRINFOT hints;
  PSOCKADDR pSockAddr;
  char server[MAX_PATH];
  char chPort[6];

  memset(server, 0x00, sizeof(server));
  memset(chPort, 0x00, sizeof(chPort));
  memset(&hints, 0x00, sizeof(hints));
  pAI = NULL;
  opt = &owner->mSocket->opt;

  if ((err = __open(owner)) != 0) return err;

  if (owner->mSocket->state != _CS_IDLE) {
    ERROUT("connect state", STATE_ERR);
    return STATE_ERR;
  }

  strncpy(server, opt->host, MAX_PATH);
  sprintf(chPort, "%d", opt->port);

  if (strcmp(server, "localhost") == 0)
    hints.ai_family = AF_INET;
  else
    hints.ai_family = AF_UNSPEC;
  if (opt->udp_flg)
    hints.ai_socktype = SOCK_DGRAM;
  else
    hints.ai_socktype = SOCK_STREAM;

  if ((err = getaddrinfo(server, chPort, &hints, &pAI)) != 0) {
#ifdef _WIN32
    ERROUT("getaddrinfo", WSAGetLastError());
#else
    ERROUT("getaddrinfo", err);
#endif
    return CONNECT_ERR;
  }

  owner->mSocket->fd =
      socket(pAI->ai_family, pAI->ai_socktype, pAI->ai_protocol);
  if (owner->mSocket->fd == INVALID_SOCKET) {
    freeaddrinfo(pAI);
#ifdef _WIN32
    ERROUT("socket", WSAGetLastError());
#else
    ERROUT("socket", errno());
#endif
    return CONNECT_ERR;
  }

  if (!opt->nag_flg) {
    optlen = sizeof(option);
    option = 1;
    if ((setsockopt(owner->mSocket->fd, IPPROTO_TCP, TCP_NODELAY,
                    (char*)&option, optlen)) != 0) {
#ifdef _WIN32
      ERROUT("getaddrinfo", WSAGetLastError());
#else
      ERROUT("getaddrinfo", err);
#endif
      return CONNECT_ERR;
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

  if (connect(owner->mSocket->fd, (PSOCKADDR)pAI->ai_addr, pAI->ai_addrlen) <
      0) {
    freeaddrinfo(pAI);
#ifdef _WIN32
    ERROUT("connect", WSAGetLastError());
#else
    ERROUT("socket", errno());
#endif
    return CONNECT_ERR;
  }

  if (opt->ssl_flg == 1) {
    if (owner->mSocket->ssl_st->fds.p_flg == 0) {
      __load_cert_file(owner, 0, 0, 0, 0);
    }

    if ((err = __ssl_connect(owner)) != 0) return err;
  }

  owner->mSocket->state = _CS_REQ_STARTED;
  return 0;
}

int __ssl_connect(socket_function* owner) {
  socket_ssl* ssl_st = owner->mSocket->ssl_st;

  ssl_st->fds.ssl = SSL_new(ssl_st->ctx);
  if (ssl_st->fds.ssl == NULL) return __sslErr(__FILE__, __LINE__, "SSL_new");

  if (!SSL_set_fd(ssl_st->fds.ssl, owner->mSocket->fd))
    return __sslErr(__FILE__, __LINE__, "SSL_set_fd");

  SSL_set_connect_state(ssl_st->fds.ssl);

  SSL_set_tlsext_host_name(ssl_st->fds.ssl, owner->mSocket->opt.host);

  if (SSL_connect(ssl_st->fds.ssl) != 1)
    return __sslErr(__FILE__, __LINE__, "SSL_connect");

  ssl_st->fds.p_flg = 2;
  return 0;
}

int __send(socket_function* owner, const char* buf, int length) {
  int offset = 0, err = 0;
  socket_buff* mBuf = 0;

  mBuf = owner->mSocket->buf;
  if (owner->mSocket->state != _CS_REQ_STARTED ||
      owner->mSocket->state != _CS_REQ_SENT ||
      owner->mSocket->state != _CS_REQ_RECV) {
    ERROUT("send state", owner->mSocket->state);
    return STATE_ERR;
  }

  if (mBuf == 0x00) {
    return __bio_write(owner->mSocket, buf, length);
  }

  if (owner->mSocket->state == _CS_REQ_RECV && !IsEmpty(mBuf)) {
    if (owner->mSocket->opt.cls_flg == 1) {
      WARNING("clean buff from server");
      if ((err = __fin(owner)) < 0) {
        return err;
      }
    } else {
      ERROUT("send state", owner->mSocket->state);
      return STATE_ERR;
    }
  }
  mBuf->w = (mBuf->w == -1) ? 0 : mBuf->w;
  while (MSGBUF_32K - mBuf->w < length) {  // 缓存区容量 < 客户数据
    memcpy(mBuf->p + mBuf->w, buf + offset, MSGBUF_32K - mBuf->w);
    offset += MSGBUF_32K - mBuf->w;
    if (__bio_write(owner->mSocket, mBuf->p + mBuf->r, MSGBUF_32K - mBuf->r) < 0) {
      return err;
    }
    mBuf->w = 0;
    mBuf->r = 0;
  }
  // 缓存区容量 >= 客户数据
  memcpy(mBuf->p + mBuf->w, buf + offset, length - offset);
  mBuf->w += length - offset;

  return length;
}

int __recv(socket_function* owner, const char* buf, int length) {
  int offset = 0, err = 0;
  socket_buff* mBuf = 0;

  mBuf = owner->mSocket->buf;
  if (owner->mSocket->state != _CS_REQ_SENT ||
      owner->mSocket->state != _CS_REQ_RECV) {
    ERROUT("recv", STATE_ERR);
    return STATE_ERR;
  }

  if (mBuf == 0x00) {
    return __bio_read(owner->mSocket, buf, length);
  }

  if (owner->mSocket->state == _CS_REQ_SENT && !IsEmpty(mBuf)) {
    if ((err = __fin(owner)) < 0) {
      return err;
    }
  }

  // 读缓冲数据长度
  if (mBuf->w == 0) {  // 缓冲区已空
  NEXT:
    if ((err = __bio_read(owner->mSocket, mBuf->p, MSGBUF_32K)) < 0) {
      return err;
    }
  }

  mBuf->w = (mBuf->w == -1) ? 0 : mBuf->w;
  if (mBuf->w - mBuf->r <= length - offset) {  // 缓冲区未读数据 <= 客户区长度
    memcpy(buf + offset, mBuf->p + mBuf->r, mBuf->w - mBuf->r);
    offset += mBuf->w - mBuf->r;
    if (err != MSGBUF_32K) {
      return offset;
    } else {
      goto NEXT;
    }
  } else {  // 缓冲区未读数据 > 客户区长度
    memcpy(buf + offset, mBuf->p + mBuf->r, length - offset);
    mBuf->r += length - offset;
    return length;
  }
}
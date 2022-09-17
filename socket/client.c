#ifdef _SOCKET_SERVER
#undef _SOCKET_SERVER
#endif
#include "socket.h"

socket_function* initClient(socket_option* opt) {
  int buf = 0, err = 0;
  socket_function* fun = 0;
  socket_base* mSocket = 0;
  socket_ssl* ssl_st = 0;
  socket_buff* rw = 0;

  opt->timeout = opt->timeout ? opt->timeout : 30;

  if ((err = __optchk(opt)) < 0) {
    ERROUT("socket_option", err);
    return err;
  }

  fun = (socket_function*)malloc(sizeof(socket_function));
  if (fun == 0) {
    ERROUT("malloc", __errno());
    return MEMORY_ERR;
  }

  mSocket = (socket_base*)malloc(sizeof(socket_base));
  if (mSocket == 0) {
    ERROUT("malloc", __errno());
    return MEMORY_ERR;
  }

  ssl_st = (socket_ssl*)malloc(sizeof(socket_ssl));
  if (ssl_st == 0) {
    ERROUT("malloc", __errno());
    return MEMORY_ERR;
  }
  memset(ssl_st, 0x00, sizeof(socket_ssl));

  if (opt->nag_flg == 2) {
    rw = (socket_buff*)malloc(sizeof(socket_buff) + MSGBUF_32K);
    if (rw == 0) {
      ERROUT("malloc", __errno());
      return MEMORY_ERR;
    }
    rw->r = 0;
    rw->w = -1;
  }

  fun->mSocket = mSocket;
  fun->connect = __connect;
  fun->fin = __fin;
  fun->send = __send;
  fun->recv = __recv;
  fun->load_cert_file = __load_cert_file;
  fun->ssl_connect = __ssl_connect;

  mSocket->opt = *opt;
  mSocket->fd = INVALID_SOCKET;
  mSocket->state = _CS_IDLE;
  mSocket->buf = rw;
  mSocket->ssl_st = ssl_st;
  mSocket->client = 0x00;
  mSocket->opt.host = (char*)malloc(strlen(opt->host) + 1);
  strcpy(mSocket->opt.host, opt->host);
#ifndef _WIN32
  signal(SIGPIPE, SIG_IGN);
#endif
  return fun;
}

int __connect(socket_function* owner) {
  int err = 0;
  int optlen, option;
  socket_option* opt;
  ADDRINFOT* pAI = NULL;
  ADDRINFOT hints;
  PSOCKADDR pSockAddr;
  char server[HOSTLEN];
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

  strncpy(server, opt->host, HOSTLEN);
  sprintf(chPort, "%d", opt->port);

  if (strcmp(server, "localhost") == 0)
    hints.ai_family = AF_INET;
  else
    hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if ((err = getaddrinfo(server, chPort, &hints, &pAI)) != 0) {
    ERROUT("getaddrinfo", __errno());
    return CONNECT_ERR;
  }

  owner->mSocket->fd =
      socket(pAI->ai_family, pAI->ai_socktype, pAI->ai_protocol);
  if (owner->mSocket->fd == INVALID_SOCKET) {
    freeaddrinfo(pAI);
    ERROUT("socket", __errno());
    return CONNECT_ERR;
  }

  if (!opt->nag_flg) {
    optlen = sizeof(option);
    option = 1;
    if ((setsockopt(owner->mSocket->fd, IPPROTO_TCP, TCP_NODELAY,
                    (char*)&option, optlen)) != 0) {
      ERROUT("getaddrinfo", __errno());
      return CONNECT_ERR;
    }
  }

  if (connect(owner->mSocket->fd, (PSOCKADDR)pAI->ai_addr, pAI->ai_addrlen) <
      0) {
    freeaddrinfo(pAI);
    ERROUT("socket", __errno());
    return CONNECT_ERR;
  }

  if (opt->ssl_flg == 1) {
    if (owner->mSocket->ssl_st->p_flg == 0) {
      __load_cert_file(owner, _SSLV23_CLIENT, 0, 0, 0);
    }

    if ((err = __ssl_connect(owner)) != 0) return err;
  }

  owner->mSocket->state = _CS_REQ_STARTED;
  return 0;
}

int __ssl_connect(socket_function* owner) {
  socket_ssl* ssl_st = owner->mSocket->ssl_st;

  ssl_st->ssl = SSL_new(ssl_st->ctx);
  if (ssl_st->ssl == NULL)
    return __sslErr(__FILE__, __LINE__, __errno(), "SSL_new");

  if (!SSL_set_fd(ssl_st->ssl, owner->mSocket->fd))
    return __sslErr(__FILE__, __LINE__, __errno(), "SSL_set_fd");

  SSL_set_connect_state(ssl_st->ssl);

  SSL_set_tlsext_host_name(ssl_st->ssl, owner->mSocket->opt.host);

  if (SSL_connect(ssl_st->ssl) != 1)
    return __sslErr(__FILE__, __LINE__, __errno(), "SSL_connect");

  ssl_st->p_flg = 2;
  return 0;
}

int __send(socket_function* owner, const char* buf, int length) {
  int offset = 0, err = 0;
  socket_buff* mBuf = 0;

  mBuf = owner->mSocket->buf;
  if (owner->mSocket->state != _CS_REQ_STARTED &&
      owner->mSocket->state != _CS_REQ_SENT &&
      owner->mSocket->state != _CS_REQ_RECV) {
    ERROUT("send state", owner->mSocket->state);
    return STATE_ERR;
  }

  if (length == 0) return 0;

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
  while (MSGBUF_32K - mBuf->w < length) {  // buff size < data len
    memcpy(mBuf->p + mBuf->w, buf + offset, MSGBUF_32K - mBuf->w);
    offset += MSGBUF_32K - mBuf->w;
    err = __bio_write(owner->mSocket, mBuf->p + mBuf->r, MSGBUF_32K - mBuf->r);
    if (err < 0) {
      return err;
    }
    mBuf->w = 0;
    mBuf->r = 0;
  }
  // buff size >= data len
  memcpy(mBuf->p + mBuf->w, buf + offset, length - offset);
  mBuf->w += length - offset;

  return length;
}

int __recv(socket_function* owner, const char* buf, int length) {
  int offset = 0, err = 0;
  socket_buff* mBuf = 0;

  mBuf = owner->mSocket->buf;
  if (owner->mSocket->state != _CS_REQ_STARTED &&
      owner->mSocket->state != _CS_REQ_SENT &&
      owner->mSocket->state != _CS_REQ_RECV) {
    ERROUT("recv", STATE_ERR);
    return STATE_ERR;
  }

  if (length == 0) return 0;

  if (mBuf == 0x00) {
    return __bio_read(owner->mSocket, buf, length);
  }

  if (owner->mSocket->state == _CS_REQ_SENT && !IsEmpty(mBuf)) {
    if ((err = __fin(owner)) < 0) {
      return err;
    }
  }

  //
  if (mBuf->w == 0) {  // buff empty
  NEXT:
    if ((err = __bio_read(owner->mSocket, mBuf->p, MSGBUF_32K)) < 0) {
      return err;
    }
  }

  mBuf->w = (mBuf->w == -1) ? 0 : mBuf->w;
  if (mBuf->w - mBuf->r <= length - offset) {  // buff not read <= user buff len
    memcpy(buf + offset, mBuf->p + mBuf->r, mBuf->w - mBuf->r);
    offset += mBuf->w - mBuf->r;
    if (err != MSGBUF_32K) {
      return offset;
    } else {
      goto NEXT;
    }
  } else {  // buff not read > user buff len
    memcpy(buf + offset, mBuf->p + mBuf->r, length - offset);
    mBuf->r += length - offset;
    return length;
  }
}

#ifndef _SOCKET_SERVER
#define _SOCKET_SERVER
#endif
#include "socket.h"

socket_function* initServer(socket_option* opt, callback cb, char* msg) {
  int buf = 0, err = 0;
  char* _msg = 0;
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

  mSocket = (socket_base*)malloc(sizeof(socket_base));
  if (mSocket == 0) {
    ERROUT("malloc", __errno());
    return 0;
  }

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

  fun->mSocket = mSocket;
  fun->callback = cb;
  fun->heloMsg = 0;
  fun->listen = __bio_listen;
  fun->close = __close;
  fun->fin = __fin;
  fun->send = __send;
  fun->recv = __recv;
  fun->ssl_bind = __ssl_bind;
  fun->load_cert_file = __load_cert_file;

  if (msg != 0) {
    _msg = (char*)malloc(strlen(msg) + 1);
    if (_msg == 0) {
      ERROUT("malloc", __errno());
      return 0;
    }
    strcpy(_msg, msg);
    fun->heloMsg = _msg;
  }

  mSocket->opt = *opt;
  mSocket->fd = INVALID_SOCKET;
  mSocket->state = _CS_IDLE;
  mSocket->buf = NULL;
  mSocket->client = fds;
  mSocket->ssl_st = ssl_st;
  mSocket->opt.host = (char*)malloc(strlen(opt->host) + 1);
  strcpy(mSocket->opt.host, opt->host);

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
  char server[HOSTLEN];
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

  strncpy(server, opt->host, HOSTLEN);
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
    ERROUT("socket", __errno());
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
    ERROUT("bind", __errno());
#endif
    return BIND_ERR;
  }

  if (listen(mSocket->fd, BACKLOG) < 0) {
    freeaddrinfo(pAI);
#ifdef _WIN32
    ERROUT("listen", WSAGetLastError());
#else
    ERROUT("listen", __errno());
#endif
    return BIND_ERR;
  }

  if (opt->ssl_flg == 1) {
    if (owner->mSocket->ssl_st->p_flg == 0) {
      __load_cert_file(owner, 0, 0, 0, 0);
    }

    if ((err = __ssl_bind(owner, -1, 0)) != 0) return err;
  }

  mSocket->state = _CS_LISTEN;
  return 0;
}

int __ssl_bind(socket_function* owner, int group, int idx) {
  SSL* c_ssl;
  socket_ssl* ssl_st = owner->mSocket->ssl_st;

  if (owner->mSocket->opt.ssl_flg == 1) {
    if (ssl_st->p_flg == 0) {
      __load_cert_file(owner, 0, 0, 0, 0);
      ssl_st->p_flg = 1;
    }
  }

  if (ssl_st->p_flg != 2) {
    c_ssl = SSL_new(ssl_st->ctx);
    if (c_ssl == NULL) return __sslErr(__FILE__, __LINE__, "SSL_new");

    if (!SSL_set_fd(c_ssl, owner->mSocket->fd))
      return __sslErr(__FILE__, __LINE__, "SSL_set_fd");

    SSL_set_accept_state(c_ssl);
    SSL_set_tlsext_host_name(c_ssl, owner->mSocket->opt.host);

    if (SSL_accept(c_ssl) != 1) {
      return __sslErr(__FILE__, __LINE__, "SSL_connect");
    }

    ssl_st->ssl = c_ssl;

    ssl_st->p_flg = 2;
  }

  if (group != -1) {
    if (owner->mSocket->client[group].cfd[idx] != INVALID_SOCKET) {
      c_ssl = ssl_st->fds[group].ssl[idx] = SSL_new(ssl_st->ctx);
      if (c_ssl == NULL) return __sslErr(__FILE__, __LINE__, "SSL_new");

      if (!SSL_set_fd(c_ssl, owner->mSocket->client[group].cfd[idx]))
        return __sslErr(__FILE__, __LINE__, "SSL_set_fd");

      SSL_set_accept_state(c_ssl);
      SSL_set_tlsext_host_name(c_ssl, owner->mSocket->opt.host);

      if (SSL_accept(c_ssl) != 1) {
        return __sslErr(__FILE__, __LINE__, "SSL_connect");
      }

      ssl_st->fds[group].ssl[idx] = c_ssl;
      ssl_st->fds[group].p_flg[idx] = 2;
    }
  }

  return 0;
}

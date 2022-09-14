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
  socket_ssl_fd* ssl_fd = 0;

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

  if (opt->ssl_flg == 1) {
    ssl_fd = (socket_ssl_fd*)malloc(sizeof(socket_ssl_fd));
    if (ssl_fd == 0) {
      ERROUT("malloc", __errno());
      return MEMORY_ERR;
    }
  }

  ssl_st = (socket_ssl*)malloc(sizeof(socket_ssl));
  if (ssl_st == 0) {
    ERROUT("malloc", __errno());
    return MEMORY_ERR;
  }
  memset(ssl_st, 0x00, sizeof(socket_ssl));
  ssl_st->fds = ssl_fd;
  ssl_st->p_flg = 0;

  fds = (socket_fd*)malloc(sizeof(socket_fd) * CT_NUM);
  if (fds == 0) {
    ERROUT("malloc", __errno());
    return MEMORY_ERR;
  }
  for (int i = 0; i < CT_NUM; i++) {
    for (int j = 0; j < MAX_CONNECT; j++) {
      fds[i].st[j].fd = INVALID_SOCKET;
      fds[i].st[j].shutdown = 0;
      fds[i].st[j].tasklock = 0;
      fds[i].st[j].tasknum = 0;
    }
    fds[i].use = 0;
  }

  fun->mSocket = mSocket;
  fun->callback = cb;
  fun->heloMsg = 0;
  fun->listen = __bio_listen;
  fun->fin = __fin;
  fun->send = __send;
  fun->recv = __recv;
  fun->ssl_bind = __ssl_bind;
  fun->load_cert_file = __load_cert_file;

  if (msg != 0) {
    _msg = (char*)malloc(strlen(msg) + 1);
    if (_msg == 0) {
      ERROUT("malloc", __errno());
      return MEMORY_ERR;
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
  if (opt->host) {
    mSocket->opt.host = (char*)malloc(strlen(opt->host) + 1);
    strcpy(mSocket->opt.host, opt->host);
  } else {
    mSocket->opt.host = 0x00;
  }

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

  if (opt->host) {
    strncpy(server, opt->host, HOSTLEN);
  } else {
    strncpy(server, "0.0.0.0", 8);
  }
  sprintf(chPort, "%d", opt->port);

  if (strcmp(server, "localhost") == 0)
    hints.ai_family = AF_INET;
  else
    hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if ((err = getaddrinfo(server, chPort, &hints, &pAI)) != 0) {
    ERROUT("getaddrinfo", __errno());
    return BIND_ERR;
  }

  mSocket->fd = socket(pAI->ai_family, pAI->ai_socktype, pAI->ai_protocol);
  if (mSocket->fd == INVALID_SOCKET) {
    freeaddrinfo(pAI);
    ERROUT("socket", __errno());
    return BIND_ERR;
  }

  optlen = sizeof(option);
  option = 1;
  if ((err = setsockopt(mSocket->fd, SOL_SOCKET, SO_REUSEADDR, &option,
                        optlen)) != 0) {
    ERROUT("setsockopt", __errno());
    return BIND_ERR;
  }

  if (opt->nag_flg == 1) {
    optlen = sizeof(option);
    option = 1;
    if ((setsockopt(mSocket->fd, IPPROTO_TCP, TCP_NODELAY, &option, optlen)) !=
        0) {
      ERROUT("setsockopt", __errno());
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
    ERROUT("bind", __errno());
    return BIND_ERR;
  }

  if (listen(mSocket->fd, BACKLOG) < 0) {
    freeaddrinfo(pAI);
    ERROUT("listen", __errno());
    return BIND_ERR;
  }

  option = 1;
#ifndef _WIN32
  if (ioctl(mSocket->fd, FIONBIO, &option))
#else
  if (ioctlsocket(mSocket->fd, FIONBIO, &option))
#endif
  {
    ERROUT("ioctl", __errno());
    return BIND_ERR;
  }

  if (opt->ssl_flg == 1) {
    if (owner->mSocket->ssl_st->p_flg == 0) {
      __load_cert_file(owner, 0, 0, 1, 0);
    }
  }

  mSocket->state = _CS_LISTEN;
  return 0;
}

SSL* __ssl_bind(socket_function* owner, SOCKET fd) {
  SSL* c_ssl;
  socket_ssl* ssl_st = owner->mSocket->ssl_st;

  if (ssl_st->p_flg == 0) {
    __load_cert_file(owner, 0, 0, 1, 0);
    ssl_st->p_flg = 1;

    ssl_st->fds = (socket_ssl_fd*)malloc(sizeof(socket_ssl_fd));
    if (ssl_st->fds == 0) {
      ERROUT("malloc", __errno());
      return MEMORY_ERR;
    }
  }

  if (fd != INVALID_SOCKET) {
    c_ssl = SSL_new(ssl_st->ctx);
    if (c_ssl == NULL) return __sslErr(__FILE__, __LINE__, "SSL_new");

    if (!SSL_set_fd(c_ssl, fd))
      return __sslErr(__FILE__, __LINE__, "SSL_set_fd");

    SSL_set_accept_state(c_ssl);

    if (SSL_accept(c_ssl) != 1) {
      return __sslErr(__FILE__, __LINE__, "SSL_accept");
    }
  }

  return c_ssl;
}

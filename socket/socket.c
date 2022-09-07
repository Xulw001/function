#include "socket.h"

int __optchk(socket_option* opt) {
  char flg =
      opt->udp_flg | opt->aio_flg | opt->nio_flg | opt->cls_flg | opt->ssl_flg;
  if (flg < 0 || flg > 1) return OPT_FLG;

  if (opt->ssl_flg < 0 || opt->nag_flg > 2) return OPT_FLG;

  if (opt->port < 0 || opt->port > 65536) return OPT_PORT;

  if (opt->host == 0 || opt->host[0] == '\0') return OPT_HOST;
}

int __open(socket_function* owner) {
#ifdef _WIN32
  WSADATA wsaData;
  WORD wVersion;
  wVersion = MAKEWORD(2, 2);
  if (WSAStartup(wVersion, &wsaData) != 0) {
    ERROUT("WSAStartup", __errno());
    return __errno();
  }

  if (wVersion != wsaData.wVersion) {
    WSACleanup();
    ERROUT("WSAStartup", WAS_VER);
    return WAS_VER;
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

int __sslErr(char* file, int line, char* fun) {
  unsigned long ulErr = 0;
  char* pTmp = NULL;
  char msg[1024];
  memset(msg, 0x00, sizeof(msg));
  ulErr = ERR_get_error();
  pTmp = (char*)ERR_reason_error_string(ulErr);
  strncpy(msg, pTmp, 1024);
  ERR_free_strings();
#ifdef _DEBUG
  printf("error appear at %s:%d in %s, errno = %d, message = %s ", file, line,
         fun, ulErr, msg);
#endif
  return ulErr;
}

int __sslChk(SSL* ssl, int ret) {
  switch (SSL_get_error(ssl, ret)) {
    case SSL_ERROR_NONE:         // ok
    case SSL_ERROR_ZERO_RETURN:  // close
      return 0;
    case SSL_ERROR_WANT_READ:     // read again
    case SSL_ERROR_WANT_WRITE:    // write again
    case SSL_ERROR_WANT_ACCEPT:   // accept again
    case SSL_ERROR_WANT_CONNECT:  // connect again
      return 1;
    default:
      return -1;
  }
}

int __load_cert_file(socket_function* owner, const char* key_file,
                     const char* cert_file, int sslV, int filev) {
  const SSL_METHOD* meth;
  socket_ssl* ssl_st = owner->mSocket->ssl_st;
#ifdef _WIN32
  while (RAND_status() == 0)
    ;
#endif
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  if (owner->mSocket->opt.udp_flg) {
    sslV += _DTLS_CLIENT;
  }
  switch (sslV) {
    case _SSLV23_CLIENT:
      meth = SSLv23_client_method();
      break;
    case _SSLV23_SERVER:
      meth = SSLv23_server_method();
      break;
    case _TLSV1_CLIENT:
      meth = TLSv1_client_method();
      break;
    case _TLSV1_SERVER:
      meth = TLSv1_server_method();
      break;
    case _TLSV11_CLIENT:
      meth = TLSv1_1_client_method();
      break;
    case _TLSV11_SERVER:
      meth = TLSv1_1_server_method();
      break;
    case _TLSV12_CLIENT:
      meth = TLSv1_2_client_method();
      break;
    case _TLSV12_SERVER:
      meth = TLSv1_2_server_method();
      break;
    case _DTLS_CLIENT:
      meth = DTLS_client_method();
      break;
    case _DTLS_SERVER:
      meth = DTLS_server_method();
      break;
    case _DTLSV1_CLIENT:
      meth = DTLSv1_client_method();
      break;
    case _DTLSV1_SERVER:
      meth = DTLSv1_server_method();
      break;
    case _DTLSV12_CLIENT:
      meth = DTLSv1_2_client_method();
      break;
    case _DTLSV12_SERVER:
      meth = DTLSv1_2_server_method();
      break;
  }

  ssl_st->ctx = SSL_CTX_new(meth);
  if (ssl_st->ctx == NULL) return __sslErr(__FILE__, __LINE__, "SSL_CTX_new");

  long ctx_options = SSL_OP_ALL;
  ctx_options |= SSL_OP_NO_TICKET;
  ctx_options |= SSL_OP_NO_COMPRESSION;
  ctx_options &= ~SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG;
  ctx_options &= ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
  ctx_options |= SSL_OP_NO_SSLv2;
  ctx_options |= SSL_OP_NO_SSLv3;

  SSL_CTX_set_max_proto_version(ssl_st->ctx, 0);
  SSL_CTX_set_options(ssl_st->ctx, ctx_options);
  SSL_CTX_set_post_handshake_auth(ssl_st->ctx, 1);

  X509_STORE_set_flags(SSL_CTX_get_cert_store(ssl_st->ctx),
                       X509_V_FLAG_TRUSTED_FIRST);

  X509_STORE_set_flags(SSL_CTX_get_cert_store(ssl_st->ctx),
                       X509_V_FLAG_PARTIAL_CHAIN);

  if (key_file && cert_file) {
    filev = (filev == 0) ? SSL_FILETYPE_PEM : filev;

    if (!SSL_CTX_use_certificate_file(ssl_st->ctx, cert_file, filev))
      return __sslErr(__FILE__, __LINE__, "SSL_CTX_use_certificate_file");

    if (!SSL_CTX_use_PrivateKey_file(ssl_st->ctx, key_file, filev))
      return __sslErr(__FILE__, __LINE__, "SSL_CTX_use_PrivateKey_file");

    if (!SSL_CTX_check_private_key(ssl_st->ctx))
      return __sslErr(__FILE__, __LINE__, "SSL_CTX_check_private_key");

    ssl_st->key_file = key_file;
    ssl_st->cert_file = cert_file;
  }

  int verifypeer = 0;  // TODO
  SSL_CTX_set_verify(ssl_st->ctx,
                     verifypeer ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);

  if (sslV % 2) {
    SSL_CTX_set_session_cache_mode(ssl_st->ctx, SSL_SESS_CACHE_NO_AUTO_CLEAR);
  } else {
    SSL_CTX_set_session_cache_mode(
        ssl_st->ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
  }

  ssl_st->p_flg = 1;

  return 0;
}

int __fin(socket_function* owner) {
  int err = 0, rtv = 0;
  socket_buff* buff = 0;

  buff = owner->mSocket->buf;
  switch (owner->mSocket->state) {
    case _CS_REQ_SENT:
      if (__bio_write(owner->mSocket, buff->p + buff->r, buff->w - buff->r) <
          0) {
        return err;
      }
      break;
    case _CS_REQ_RECV:
      while ((rtv = __bio_read(owner->mSocket, buff->p, MSGBUF_32K)) != 0) {
        if (rtv < 0) {
          return err;
        } else if (rtv < MSGBUF_32K) {
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
      SSL_free(owner->mSocket->ssl_st->fds[group].ssl[idx]);
      owner->mSocket->ssl_st->fds[group].ssl[idx] = 0x00;
    }
  }

  if (owner->mSocket->client != NULL) {
    if (owner->mSocket->client[group].cfd[idx]) {
#ifndef _WIN32
      close(owner->mSocket->client[group].cfd[idx]);
#else
      closesocket(owner->mSocket->client[group].cfd[idx]);
#endif
      owner->mSocket->client[group].cfd[idx] = INVALID_SOCKET;
    }
  }

  return 0;
}

int __close0(socket_function* owner) {
  if (owner->mSocket->state != _CS_REQ_STARTED) {
    ERROUT("close", STATE_ERR);
    return STATE_ERR;
  }

  if (owner->mSocket->ssl_st->ssl != NULL) {
    SSL_free(owner->mSocket->ssl_st->ssl);
    owner->mSocket->ssl_st->ssl = 0;

    socket_ssl_fd* fd = owner->mSocket->ssl_st->fds;
    for (int i = 0; i < CT_NUM; i++) {
      for (int k = 0; k < MAX_CONNECT; k++) {
        if (fd[i].ssl[k]) {
          SSL_free(fd[i].ssl[k]);
          fd[i].ssl[k] = 0x00;
        }
      };
    }
  }

  if (owner->mSocket->ssl_st->ctx != NULL)
    SSL_CTX_free(owner->mSocket->ssl_st->ctx);

  socket_fd* pfd = owner->mSocket->client;
  for (int i = 0; i < CT_NUM; i++) {
    if (pfd->use == 0) continue;
    for (int k = 0; k < MAX_CONNECT; k++) {
      if (pfd[i].cfd[k]) {
#ifndef _WIN32
        close(pfd[i].cfd[k]);
#else
        closesocket(pfd[i].cfd[k]);
#endif
        pfd[i].cfd[k] = INVALID_SOCKET;
      }
    }
  }
  owner->mSocket->client = 0x00;

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

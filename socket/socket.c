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

// int final(void* fun) {
//   int err = 0;
//   if (fun == NULL) {
//     return 0;
//   }

//   if ((err = ((socket_function*)fun)->close(fun)) != 0) {
//     return err;
//   }

//   if (((socket_function*)fun)->mSocket == 0) {
//     return 0;
//   }

//   if (((socket_function*)fun)->mSocket->r_buf != NULL) {
//     free(((socket_function*)fun)->mSocket->r_buf);
//     ((socket_function*)fun)->mSocket->r_buf = NULL;
//   }

//   if (((socket_function*)fun)->mSocket->w_buf != NULL) {
//     free(((socket_function*)fun)->mSocket->w_buf);
//     ((socket_function*)fun)->mSocket->w_buf = NULL;
//   }

//   if (((socket_function*)fun)->mSocket->opt.host != NULL) {
//     free(((socket_function*)fun)->mSocket->opt.host);
//     ((socket_function*)fun)->mSocket->opt.host = NULL;
//   }

//   free(((socket_function*)fun)->mSocket);
//   ((socket_function*)fun)->mSocket = NULL;

//   free(fun);
// }

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

// int __sslChk(SSL* ssl, int ret) {
//   switch (SSL_get_error(ssl, ret)) {
//     case SSL_ERROR_NONE:  // ok
//       return 0;
//     case SSL_ERROR_WANT_READ:     // read again
//     case SSL_ERROR_WANT_WRITE:    // write again
//     case SSL_ERROR_WANT_ACCEPT:   // accept again
//     case SSL_ERROR_WANT_CONNECT:  // connect again
//       return 1;
//     case SSL_ERROR_ZERO_RETURN:  // close
//     default:
//       return -1;
//   }
// }

int __load_cert_file(socket_function* owner, const char* key_file,
                     const char* cert_file, int sslV, int filev) {
  const SSL_METHOD* meth;
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

  boolean verifypeer = 0;  // TODO
  SSL_CTX_set_verify(ssl_st->ctx,
                     verifypeer ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);

  if (sslV % 2) {
    SSL_CTX_set_session_cache_mode(ssl_st->ctx, SSL_SESS_CACHE_NO_AUTO_CLEAR);
  } else {
    SSL_CTX_set_session_cache_mode(
        ssl_st->ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
  }

  ssl_st->fds.p_flg = 1;

  return 0;
}

socket_function* initClient(socket_option* opt) {
  int buf = 0, err = 0;
  socket_function* fun = 0;
  socket_base* mSocket = 0;
  socket_ssl* ssl_st = 0;
  socket_buff* rw = 0;

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
  fun->mSocket = mSocket;
  fun->connect = __connect;
  fun->close = __close;
  fun->fin = __fin;
  fun->send = __send;
  fun->recv = __recv;
  fun->load_cert_file = __load_cert_file;
  fun->ssl_connect = __ssl_connect;

  mSocket = (socket_base*)malloc(sizeof(socket_base));
  if (mSocket == 0) {
    ERROUT("malloc", __errno());
    return 0;
  }
  mSocket->opt = *opt;
  mSocket->fd = INVALID_SOCKET;
  mSocket->state = _CS_IDLE;
  mSocket->buf = rw;
  mSocket->ssl_st = ssl_st;
  mSocket->client = 0x00;
  mSocket->opt.host = (char*)malloc(strlen(opt->host) + 1);
  memset(mSocket->opt.host, 0x00, strlen(opt->host) + 1);
  strcmp(mSocket->opt.host, opt->host);

  ssl_st = (socket_ssl*)malloc(sizeof(socket_ssl));
  if (ssl_st == 0) {
    ERROUT("malloc", __errno());
    return 0;
  }
  memset(ssl_st, 0x00, sizeof(socket_ssl));

  if (opt->nag_flg == 2) {
    rw = (socket_buff*)malloc(sizeof(socket_buff) + MSGBUF_32K);
    if (rw == 0) {
      ERROUT("malloc", __errno());
      return 0;
    }
    rw->r = 0;
    rw->w = -1;
  }

  return fun;
}

// int __bio_write(socket_function* owner, int* err) {
//   fd_set fds;
//   int nfds;
//   int size, totalSize = 0;
//   socket_base* mSocket = 0;
//   socket_buff* mBuf = 0;
//   struct timeval tvTimeOut;
//   mSocket = owner->mSocket;

//   if (mSocket->fd == INVALID_SOCKET) {
//     if ((*err = __connect(owner)) != 0) return -1;
//   }

//   if (owner->mSocket->opt.rrw_flg == 1) {
//     mBuf = owner->mSocket->w_buf;
//   } else {
//     mBuf = owner->mSocket->r_buf;
//   }

//   while (totalSize < mBuf->length) {
//     tvTimeOut.tv_sec = mSocket->opt.timeout;
//     tvTimeOut.tv_usec = 0;
//     FD_ZERO(&fds);
//     FD_SET(mSocket->fd, &fds);
// #ifdef _WIN32
//     nfds = select(1, NULL, &fds, NULL, &tvTimeOut);
// #else
//     nfds = select(mSocket->fd + 1, NULL, &fds, NULL, &tvTimeOut);
// #endif
//     if (nfds == 0) {
//       return 0;
//     } else if (nfds < 0) {
//       ERROUT("select", errno);
//       *err = errno;
//       return -1;
//     }

//     if (FD_ISSET(mSocket->fd, &fds)) {
//       if (mSocket->opt.ssl_flg != 0 && mSocket->ssl_st->p_flg == 2) {
//         size = SSL_write(mSocket->ssl_st->ssl, mBuf->p + totalSize,
//                          mBuf->length - totalSize);
//         switch (__sslChk(mSocket->ssl_st->ssl, size)) {
//           case -1:
//             ERROUT("SSL_write", errno);
//             *err = errno;
//             return -1;
//           case 0:
//             totalSize += size;
//             break;
//           case 1:
//             break;
//         }
//       } else {
//         size =
//             send(mSocket->fd, mBuf->p + totalSize, mBuf->length - totalSize,
//             0);
//         if (size < 0) {
//           ERROUT("send", errno);
//           *err = errno;
//           return -1;
//         };
//         totalSize += size;
//       }
//     }
//   }
//   mSocket->state = _CS_REQ_SENT;
//   mBuf->length = 0;
//   return totalSize;
// }

// int __bio_read(socket_function* owner, int* err) {
//   fd_set fds;
//   int nfds;
//   int totalSize, size = 0;
//   socket_base* mSocket = 0;
//   socket_buff* mBuf = 0;
//   struct timeval tvTimeOut;

//   mSocket = owner->mSocket;
//   mBuf = mSocket->r_buf;
//   totalSize = 0;

//   if (mSocket->fd == INVALID_SOCKET) {
//     if ((*err = __connect(owner)) != 0) return -1;
//   }

//   do {
//     tvTimeOut.tv_sec = 0;
//     tvTimeOut.tv_usec = mSocket->opt.timeout;
//     FD_ZERO(&fds);
//     FD_SET(mSocket->fd, &fds);

// #ifdef _WIN32
//     nfds = select(1, NULL, &fds, NULL, &tvTimeOut);
// #else
//     nfds = select(mSocket->fd + 1, NULL, &fds, NULL, &tvTimeOut);
// #endif
//     if (nfds == 0) {
//       return 0;
//     } else if (nfds < 0) {
//       ERROUT("select", errno);
//       *err = errno;
//       return -1;
//     }

//     if (FD_ISSET(mSocket->fd, &fds)) {
//       if (mSocket->opt.ssl_flg != 0 && mSocket->ssl_st->p_flg == 2) {
//         size = SSL_read(mSocket->ssl_st->ssl, mBuf->p + totalSize,
//                         MSGBUF_32K - totalSize);
//         switch (__sslChk(mSocket->ssl_st->ssl, size)) {
//           case -1:
//             ERROUT("SSL_read", errno);
//             *err = errno;
//             return -1;
//           case 0:
//             totalSize += size;
//             break;
//           case 1:
//             break;
//         }
//       } else {
//         size =
//             recv(mSocket->fd, mBuf->p + totalSize, MSGBUF_32K - totalSize,
//             0);
//         if (size < 0) {
//           if (size == EAGAIN) {
//             break;
//           } else {
//             ERROUT("recv", errno);
//             *err = errno;
//             return -1;
//           }
//         }
//         totalSize += size;
//       }
//     }
//   } while (totalSize <= MSGBUF_32K);
//   mSocket->state = _CS_REQ_RECV;
//   if (mBuf->length < totalSize) {
//     mBuf->length = (totalSize << 0x10) & 0xFFFF0000;
//   } else {
//     mBuf->length = 0;
//   }
//   return 0;
// }

int __fin(socket_function* owner) {
  int err = 0, rtv = 0;
  socket_buff* buff = 0;

  buff = owner->mSocket->buf;
  switch (owner->mSocket->state) {
    case _CS_REQ_SENT:
      if (__bio_write(owner->mSocket->fd, buff + buff->r, buff->w - buff->r) <
          0) {
        return err;
      }
      break;
    case _CS_REQ_RECV:
      while ((rtv = __bio_read(owner->mSocket->fd, buff, MSGBUF_32K)) != 0) {
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

// int __send(socket_function* owner, const char* buf, int length) {
//   int size = 0, offset = 0, err = 0;
//   socket_buff* mBuf = 0;

//   if (owner->mSocket->opt.rrw_flg == 1) {
//     mBuf = owner->mSocket->w_buf;
//   } else {
//     mBuf = owner->mSocket->r_buf;
//   }

//   if (owner->mSocket->state != _CS_REQ_STARTED ||
//       owner->mSocket->state != _CS_REQ_SENT ||
//       owner->mSocket->state != _CS_REQ_RECV) {
//     ERROUT("send state", owner->mSocket->state);
//     return STATE_ERR;
//   }

//   if (owner->mSocket->opt.rrw_flg == 0 &&
//       owner->mSocket->state == _CS_REQ_RECV && mBuf->length != 0) {
//     if (owner->mSocket->opt.cls_flg == 1) {
//       WARNING("send state", owner->mSocket->state);
//       if ((err = __fin(owner)) < 0) {
//         return err;
//       }
//     } else {
//       ERROUT("send state", owner->mSocket->state);
//       return STATE_ERR;
//     }
//   }

//   while (MSGBUF_32K - mBuf->length < length) {  // 缓存区容量 < 客户数据
//     memcpy(mBuf->p + mBuf->length, buf + offset, MSGBUF_32K - mBuf->length);
//     offset += size - mBuf->length;
//     mBuf->length = size;
//     if (__bio_write(owner, &err) < 0) {
//       return err;
//     }
//   }
//   // 缓存区容量 >= 客户数据
//   memcpy(mBuf->p + mBuf->length, buf + offset, length - offset);
//   mBuf->length += length - offset;

//   return length;
// }

// int __recv(socket_function* owner, const char* buf, int length) {
//   int size = 0, offset = 0, rdlen = 0, flag = 0, err = 0;
//   socket_buff* mBuf = 0;

//   mBuf = owner->mSocket->r_buf;
//   if (owner->mSocket->state != _CS_REQ_SENT ||
//       owner->mSocket->state != _CS_REQ_RECV) {
//     ERROUT("recv", STATE_ERR);
//     return STATE_ERR;
//   }

//   if (owner->mSocket->opt.rrw_flg == 0 &&
//       owner->mSocket->state == _CS_REQ_SENT && mBuf->length != 0) {
//     if ((err = __fin(owner)) < 0) {
//       return err;
//     }
//   }

//   // 读缓冲数据长度
//   size = (mBuf->length) >> 0x10 & 0x0000FFFF;
//   if (size == 0x0000) {
//     size = MSGBUF_32K;
//     rdlen = mBuf->length;
//   } else {
//     rdlen = mBuf->length & 0x0000FFFF;  // 已读长度
//     flag = 1;                           // socket已空
//   }

//   if (rdlen >= size) {  // 缓冲区已空
//   NEXT:
//     if (__bio_read(owner, &err) < 0) {
//       return err;
//     }

//     rdlen = 0;
//     if (mBuf->length == 0) {
//       size = MSGBUF_32K;
//     } else {
//       size = (mBuf->length) >> 0x10 & 0x0000FFFF;
//       flag = 1;  // socket已空
//     }
//   }

//   if (size - rdlen <= length - offset) {  // 缓冲区未读数据 <= 客户区长度
//     memcpy(buf + offset, mBuf->p + rdlen, size - rdlen);
//     offset += size - rdlen;
//     if (flag) {
//       return offset;
//     } else {
//       goto NEXT;
//     }
//   } else {  // 缓冲区未读数据 > 客户区长度
//     memcpy(buf + offset, mBuf->p + rdlen, length - offset);
//     mBuf->length += length - offset;
//     return length;
//   }
// }

// int __close0(socket_function* owner) {
//   if (owner->mSocket->state != _CS_REQ_STARTED) {
//     ERROUT("close", STATE_ERR);
//     return STATE_ERR;
//   }

//   if (owner->mSocket->ssl_st->ssl != NULL)
//     SSL_free(owner->mSocket->ssl_st->ssl);
//   if (owner->mSocket->ssl_st->ctx != NULL)
//     SSL_CTX_free(owner->mSocket->ssl_st->ctx);

//   if (owner->mSocket->fd != INVALID_SOCKET) {
// #ifndef _WIN32
//     ::close(owner->mSocket->fd);
// #else
//     closesocket(owner->mSocket->fd);
//     WSACleanup();
// #endif
//   }
//   owner->mSocket->state = _CS_IDLE;
//   return 0;
// }

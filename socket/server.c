// #include <stdio.h>
// #include <stdlib.h>
// #include <unistd.h>

#ifndef _SOCKET_SERVER
#define _SOCKET_SERVER
#endif
#include "socket.h"

// #ifdef DEBUG

socket_function* initServer(socket_option* opt, callback cb,
                            callbackstart start) {
  int buf = 0, err = 0;
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
  fun->mSocket = mSocket;
  fun->callback = cb;
  fun->callbackstart = start;
  fun->bind = __bind;
  fun->close = __close;
  fun->fin = __fin;
  fun->send = __send;
  fun->recv = __recv;
  fun->load_cert_file = __load_cert_file;
  fun->ssl_bind = __ssl_bind;
  fun->ssl_listen = __ssl_listen;

  mSocket = (socket_base*)malloc(sizeof(socket_base));
  if (mSocket == 0) {
    ERROUT("malloc", __errno());
    return 0;
  }
  mSocket->opt = *opt;
  mSocket->fd = INVALID_SOCKET;
  mSocket->state = _CS_IDLE;
  mSocket->buf = NULL;
  mSocket->client = fds;
  mSocket->ssl_st = ssl_st;
  mSocket->opt.host = (char*)malloc(strlen(opt->host) + 1);
  memset(mSocket->opt.host, 0x00, strlen(opt->host) + 1);
  strcmp(mSocket->opt.host, opt->host);

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

  return fun;
}

// int __bind(socket_function* owner) {
//   int err = 0;
//   int optlen, option;
//   socket_option* opt;
//   ADDRINFOT* pAI = NULL;
//   ADDRINFOT hints;
//   PSOCKADDR pSockAddr;
//   socket_base* mSocket = NULL;
//   char server[MAX_PATH];
//   char chPort[6];

//   memset(server, 0x00, sizeof(server));
//   memset(chPort, 0x00, sizeof(chPort));
//   memset(&hints, 0x00, sizeof(hints));
//   pAI = NULL;
//   mSocket = owner->mSocket;
//   opt = &mSocket->opt;

//   if ((err = __open((socket_function_client*)owner)) != 0) return err;

//   if (mSocket->state != _CS_IDLE) {
//     ERROUT("connect state", STATE_ERR);
//     return STATE_ERR;
//   }

//   strncpy(server, opt->host, MAX_PATH);
//   sprintf(chPort, "%d", opt->port);

//   if (strcmp(server, "localhost") == 0)
//     hints.ai_family = AF_INET;
//   else
//     hints.ai_family = AF_UNSPEC;
//   hints.ai_socktype = SOCK_STREAM;

//   if ((err = getaddrinfo(server, chPort, &hints, &pAI)) != 0) {
// #ifdef _WIN32
//     ERROUT("getaddrinfo", WSAGetLastError());
//     return WSAGetLastError();
// #else
//     ERROUT("getaddrinfo", err);
//     return err;
// #endif
//   }

//   mSocket->fd = socket(pAI->ai_family, pAI->ai_socktype, pAI->ai_protocol);
//   if (mSocket->fd == INVALID_SOCKET) {
//     freeaddrinfo(pAI);
// #ifdef _WIN32
//     ERROUT("socket", WSAGetLastError());
//     return WSAGetLastError();
// #else
//     ERROUT("socket", errno());
//     return errno;
// #endif
//   }

//   optlen = sizeof(option);
//   option = 1;
//   if ((err = setsockopt(mSocket->fd, IPPROTO_TCP, SO_REUSEADDR, &option,
//                         optlen)) != 0) {
// #ifdef _WIN32
//     ERROUT("setsockopt", WSAGetLastError());
//     return WSAGetLastError();
// #else
//     ERROUT("setsockopt", err);
//     return err;
// #endif
//   }

//   if (opt->nag_flg == 1) {
//     optlen = sizeof(option);
//     option = 1;
//     if ((setsockopt(mSocket->fd, IPPROTO_TCP, TCP_NODELAY, &option, optlen))
//     !=
//         0) {
// #ifdef _WIN32
//       ERROUT("getaddrinfo", WSAGetLastError());
//       return WSAGetLastError();
// #else
//       ERROUT("getaddrinfo", err);
//       return err;
// #endif
//     }
//   }

//   pSockAddr = (PSOCKADDR)pAI->ai_addr;
//   switch (pAI->ai_family) {
//     case AF_INET:
//       if (((struct sockaddr_in*)pSockAddr)->sin_port == 0)
//         ((struct sockaddr_in*)pSockAddr)->sin_port =
//         htons((u_short)opt->port);
//       break;
//     case AF_INET6:
//       if (((struct sockaddr_in6*)pSockAddr)->sin6_port == 0)
//         ((struct sockaddr_in6*)pSockAddr)->sin6_port =
//             htons((u_short)opt->port);
//       break;
//   }

//   if (bind(mSocket->fd, (PSOCKADDR)pAI->ai_addr, pAI->ai_addrlen) < 0) {
//     freeaddrinfo(pAI);
// #ifdef _WIN32
//     ERROUT("connect", WSAGetLastError());
//     return WSAGetLastError();
// #else
//     ERROUT("connect", errno());
//     return errno;
// #endif
//   }

//   if (listen(mSocket->fd, BACKLOG) < 0) {
//     freeaddrinfo(pAI);
// #ifdef _WIN32
//     ERROUT("listen", WSAGetLastError());
//     return WSAGetLastError();
// #else
//     ERROUT("listen", errno());
//     return errno;
// #endif
//   }

//   mSocket->state = _CS_LISTEN;
//   return 0;
// }

// // int __ssl_bind(socket_function* owner, int index, int group) {
// //   socket_ssl* ssl_st = owner->mSocket->ssl_st;

// //   if (owner->mSocket->opt.ssl_flg == 1) {
// //     if (ssl_st->p_flg[0] == 0) {
// //       __load_cert_file(owner, 0, 0, 0, 0);
// //       ssl_st->p_flg[0] = 1;
// //     }
// //   }

// //   ssl_st->ssl[index] = SSL_new(ssl_st->ctx);
// //   if (ssl_st->ssl[index] == NULL)
// //     return __sslErr(__FILE__, __LINE__, "SSL_new");

// //   if (!SSL_set_fd(ssl_st->ssl[index],
// //                   ((socket_base*)(owner->mSocket))[index]))
// //     return __sslErr(__FILE__, __LINE__, "SSL_set_fd");

// //   SSL_set_accept_state(ssl_st->ssl[index]);

// //   SSL_set_tlsext_host_name(ssl_st->ssl[index], owner->mSocket->opt.host);

// //   if (SSL_accept(ssl_st->ssl[index]) != 1) {
// //     return __sslErr(__FILE__, __LINE__, "SSL_connect");
// //   }

// //   ssl_st->p_flg[index] = 2;
// //   return 0;
// // }

// // int __listen(socket_function* owner) {
// //   int err;
// //   fd_set fds;
// //   int nfds, sFind, nread;
// //   SOCKET max_fd, cfd;
// //   struct sockaddr_in cliAddr;
// //   socket_base* mSocket = 0;
// //   struct timeval tvTimeOut;

// //   mSocket = (socket_base*)owner->mSocket;

// //   if (mSocket->fd == INVALID_SOCKET) {
// //     if ((err = __bind(owner)) != 0) return -1;
// //   }

// //   while (mSocket->state == _CS_LISTEN) {
// //     tvTimeOut.tv_sec = 0;
// //     tvTimeOut.tv_usec = mSocket->opt.timeout;
// //     FD_ZERO(&fds);
// //     for (int i = 1; i <= MAX_CONNECT; i++) {
// //       if (mSocket->cfd[i] == INVALID_SOCKET) continue;
// //       max_fd = (mSocket->cfd[i] > max_fd) ? mSocket->cfd[i] : max_fd;
// //       FD_SET(mSocket->cfd[i], &fds);
// //     }

// //     nfds = select(max_fd + 1, &fds, NULL, NULL, &tvTimeOut);
// //     if (nfds == 0) {
// //       continue;
// //     } else if (nfds < 0) {
// //       WARNING("select", errno);
// //       err = errno;
// //       break;
// //     }

// //     if (FD_ISSET(mSocket->fd, &fds)) {
// //       cfd = accept(mSocket->fd, (PSOCKADDR)&cliAddr, sizeof(cliAddr));
// //       if (cfd < 0) {
// //         WARNING("accept", errno);
// //         break;
// //       }

// //       sFind = 0;
// //       for (int i = 0; i < MAX_CONNECT; i++) {
// //         if (mSocket->cfd[i] < 0) {
// //           mSocket->cfd[i] = cfd;
// //           sFind = 1;

// //           if (mSocket->opt.ssl_flg != 0) {
// //             err = __ssl_bind(owner, i);
// //             if (err < 0) {
// //               ERROUT("bind", errno);
// //               break;
// //             }
// //           }

// //           err = owner->callbackstart(cfd, &cliAddr);
// //           if (err < 0) {
// //             ERROUT("start", errno);
// //             break;
// //           }

// //           break;
// //         }
// //       }
// //       if (!sFind) {
// //         WARNING("accept", "socket queue is full");
// // #ifndef _WIN32
// //         close(cfd);
// // #else
// //         closesocket(cfd);
// // #endif
// //       }
// //     }
// //     for (int i = 1; i < MAX_CONNECT; i++) {
// //       if (mSocket->cfd[i] == INVALID_SOCKET ||
// //           !FD_ISSET(mSocket->cfd[i], &fds)) {
// //         continue;
// //       }
// // #ifndef _WIN32
// //       err = ioctl(mSocket->cfd[i], FIONREAD, &nread);
// // #else
// //       err = ioctlsocket(mSocket->cfd[i], FIONREAD, &nread);
// // #endif
// //       if (err < 0) {
// //         ERROUT("callback", errno);
// // #ifndef _WIN32
// //         close(mSocket->cfd[i]);
// // #else
// //         closesocket(mSocket->cfd[i]);
// // #endif
// //         break;
// //       }

// //       if (nread == 0) {
// // #ifndef _WIN32
// //         close(mSocket->cfd[i]);
// // #else
// //         closesocket(mSocket->cfd[i]);
// // #endif
// //         mSocket->cfd[i] = INVALID_SOCKET;
// //         break;
// //       }

// //       err = owner->callback(mSocket->cfd[i], nread);
// //       if (err < 0) {
// //         ERROUT("callback", errno);
// // #ifndef _WIN32
// //         close(mSocket->cfd[i]);
// // #else
// //         closesocket(mSocket->cfd[i]);
// // #endif
// //         mSocket->cfd[i] = INVALID_SOCKET;
// //         break;
// //       }
// //     }
// //   }

// //   return err;
// // }

// int __closeClient(socket_function* owner, int index, int group) {}

// int __close1(socket_function* owner) {
//   //   if (owner->mSocket->state != _CS_LISTEN) {
//   //     ERROUT("close", STATE_ERR);
//   //     return STATE_ERR;
//   //   }

//   //   if (owner->mSocket->ssl_st.ssl != NULL)
//   //   SSL_free(owner->mSocket->ssl_st.ssl); if (owner->mSocket->ssl_st.ctx
//   !=
//   //   NULL)
//   //     SSL_CTX_free(owner->mSocket->ssl_st.ctx);

//   //   for (int i = 1; i < MAX_CONNECT; i++) {
//   //     if (((socket_base*)owner->mSocket)->cfd[i] != INVALID_SOCKET)
//   {
//   // #ifndef _WIN32
//   //       ::close(((socket_base*)owner->mSocket)->cfd[i]);
//   // #else
//   //       closesocket(((socket_base*)owner->mSocket)->cfd[i]);
//   // #endif
//   //     }
//   //   }

//   //   if (owner->mSocket->fd != INVALID_SOCKET) {
//   // #ifndef _WIN32
//   //     ::close(owner->mSocket->fd);
//   // #else
//   //     closesocket(owner->mSocket->fd);
//   //     WSACleanup();
//   // #endif
//   //   }
//   //   owner->mSocket->state = _CS_IDLE;
//   //   return 0;
// }

#include "server.h"
#ifndef _WIN32
#include <pthread.h>
#else
#include <process.h>
#include <windows.h>
#endif
#include <stdio.h>
#include <thread/lock.h>

#ifndef _WIN32
#define thrd_t pthread_t
#else
#define thrd_t uintptr_t
#endif

int InitServer(Socket* pSocket) {
  int err = 0;
  int option;
  channel_extend* psock = NULL;
  ADDRINFOT* pAI = NULL;
  ADDRINFOT hints;
  PSOCKADDR pSockAddr;
  char server[HOST_NAME_MAX];
  char chPort[6];

  psock = (channel_extend*)malloc(sizeof(channel_extend));
  if (psock == 0) {
    ERROUT("malloc", __errno());
    return -1;
  }

  memset(server, 0x00, sizeof(server));
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

  if (pSocket->opt.aio_flg == 1 || pSocket->opt.udp_flg == 1) {
    option = 1;
    if ((err = setsockopt(psock->fd, SOL_SOCKET, SO_REUSEADDR,
                          (const void*)&option, sizeof(option))) != 0) {
      ERROUT("setsockopt", __errno());
      goto ERR;
    }

#ifndef _WIN32
    option = 1;
    if ((setsockopt(psock->fd, SOL_SOCKET, SO_REUSEPORT, (const void*)&option,
                    sizeof(option))) != 0) {
      ERROUT("setsockopt", __errno());
      goto ERR;
    }
#endif
  }

  pSockAddr = (PSOCKADDR)pAI->ai_addr;
  switch (pAI->ai_family) {
    case AF_INET:
      if (((struct sockaddr_in*)pSockAddr)->sin_port == 0)
        ((struct sockaddr_in*)pSockAddr)->sin_port =
            htons((u_short)pSocket->info.port);
      break;
    case AF_INET6:
      if (((struct sockaddr_in6*)pSockAddr)->sin6_port == 0)
        ((struct sockaddr_in6*)pSockAddr)->sin6_port =
            htons((u_short)pSocket->info.port);
      option = 0;
      if (setsockopt(psock->fd, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&option,
                     sizeof(option)) == 0) {
        ERROUT("setsockopt", __errno());
        goto ERR;
      }
      break;
  }

  if (bind(psock->fd, (PSOCKADDR)pAI->ai_addr, pAI->ai_addrlen) < 0) {
    ERROUT("bind", __errno());
    goto ERR;
  }

  if (pSocket->opt.udp_flg == 0) {
    if (listen(psock->fd, BACKLOG) < 0) {
      ERROUT("listen", __errno());
      goto ERR;
    }
  } else {
    memcpy(&psock->svraddr, (PSOCKADDR)pAI->ai_addr, pAI->ai_addrlen);
  }

  if (pSocket->opt.nio_flg == 1) {
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
  psock->noblock = pSocket->opt.nio_flg;
  psock->state = _CS_IDLE;
  psock->mutex = FREE;
  pSocket->fd = psock;
  pSocket->opt.resv2 = 0x01;
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

int EndServer(Socket* socket) {
  int err = 0;
  if (socket->fd != NULL) {
    ((channel_extend*)socket->fd)->state = _CS_STOP;
    while (((channel_extend*)socket->fd)->state != _CS_END) {
#ifdef _WIN32
      Sleep(1000);
#else
      sleep(1);
#endif
    }

    err = Close(((channel_extend*)socket->fd)->fd);
    free(socket->fd);
    socket->fd = NULL;
  }
  return 0;
}

int AsyncListen(void* pSocket) { return 0; }

// int Accept(void* pSocket) {
//   channel_extend* socket = pSocket;
//   int err;
//   int size;
//   struct sockaddr_in cliAddr;
//   char sbuf[MSGBUF_8K];
//   int clen = 0;
//   while (socket->state == _CS_IDLE) {
//     clen = sizeof(struct sockaddr_in);
//     size = recvfrom(socket->fd, sbuf, MSGBUF_8K, 0, (struct
//     sockaddr*)&cliAddr,
//                     &clen);
//     if (size < 0) {
//       err = __errno();
//       if (!socket->noblock ||
//           (err != EINTR && err != EAGAIN && err != EWOULDBLOCK)) {
//         ERROUT("recvfrom", err);
//       }
//       continue;
//     }

//     err = socket->pRecv(cliAddr.sin_addr.s_addr, cliAddr.sin_port, sbuf,
//     size); if (err < 0) {
//       continue;
//     }

//     do {
//       size = socket->pSend(cliAddr.sin_addr.s_addr, cliAddr.sin_port, sbuf,
//                            MSGBUF_8K);
//       if (size <= 0) {
//         break;
//       }

//       do {
//         err = sendto(socket->fd, sbuf, size, 0, (struct sockaddr*)&cliAddr,
//                      sizeof(cliAddr));
//         if (err < 0) {
//           err = __errno();
//           if (!socket->noblock ||
//               (err != EINTR && err != EAGAIN && err != EWOULDBLOCK)) {
//             ERROUT("sendto", err);
//             break;
//           }
//           continue;
//         }
//       } while (err < 0);
//     } while (MSGBUF_8K <= size);
//   }

//   socket->state = _CS_END;
//   return 0;
// }

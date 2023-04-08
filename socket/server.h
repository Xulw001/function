#pragma once
#include "client.h"

#ifndef MAX_CONNECT
#define MAX_CONNECT 2
#endif
#ifdef _WIN32
#undef FD_SETSIZE
#define FD_SETSIZE MAX_CONNECT
#endif

typedef enum {
  _CS_IDLE,
  _CS_STOP,
  _CS_END,
} State;

typedef struct {
  SOCKET fd;
  unsigned mutex;  // lock for select
  int timeout;
  int state;
  int noblock;
  RecvCallback pRecv;
  SendCallback pSend;
  sockaddr_info svraddr;
} channel_extend;

int TCPBind(Socket* socket, RecvCallback pRecv, SendCallback pSend);
int UDPBind(Socket* socket, RecvCallback pRecv, SendCallback pSend);
u_int TCPListen(void* pSocket);
u_int UDPListen(void* pSocket);

int InitServer(Socket* socket);
int EndServer(Socket* socket);

int AsyncListen(void* pSocket);
int CallBack(SOCKET fd, RecvCallback pRecv, SendCallback pSend, int noblock,
             int init);

SOCKET UDPSocket(sockaddr_info* svrAddr, sockaddr_info* cliAddr);

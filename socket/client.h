#pragma once
#include "socket.h"

typedef struct {
  SOCKET fd;
  int timeout;
  sockaddr_info svraddr;
} channel;

int InitClient(Socket* socket);
int EndClient(Socket* socket);

int SendMsg(Socket* socket, char* buff, unsigned size);
int RecvMsg(Socket* socket, char* buff, unsigned size);
int Send(channel* socket, char* buff, unsigned size);
int Recv(channel* socket, char* buff, unsigned size);

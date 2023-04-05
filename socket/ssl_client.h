#pragma once
#include "ssl.h"
#include "client.h"

int InitSSLClient(Socket* socket);
int EndSSLClient(Socket* socket);

int SSLSendMsg(Socket* socket, char* buff, unsigned size);
int SSLRecvMsg(Socket* socket, char* buff, unsigned size);

int SSLSend(ssl_channel* socket, char* buff, unsigned size);
int SSLRecv(ssl_channel* socket, char* buff, unsigned size);
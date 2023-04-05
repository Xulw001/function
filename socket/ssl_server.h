#pragma once
#include "server.h"
#include "ssl.h"

int UDPSSLBind(Socket* socket, RecvCallback pRecv, SendCallback pSend);
int SSLBind(Socket* socket, RecvCallback pRecv, SendCallback pSend);

int InitSSLServer(Socket* socket);
int EndSSLServer(Socket* socket);
int SSLListen(void* pSocket);
int UDPSSLListen(void* pSocket);
int AsyncSSLListen(void* pSocket);
int SSLCallBack(SSL* ssl, SOCKET fd, RecvCallback pRecv, SendCallback pSend,
             int noblock, int init);
SSL* SSLAccept(SOCKET fd, SSL_CTX* ctx);
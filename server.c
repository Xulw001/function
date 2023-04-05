#define _SOCKET_SERVER
#include <stdio.h>
#include <time.h>
#ifndef _WIN32
#define SEP "/"
#else
#define SEP "\\"
#endif
#include "socket/socket.h"

int onSend(unsigned channel, int port, char* pBuf, unsigned size) {
  char buf[500];
  memset(buf, 0x00, sizeof(buf));
  time_t ctime;
  struct tm* info;
  time(&ctime);
  info = localtime(&ctime);
  strftime(buf + 128, 100, "%Y-%m-%d %H:%M:%S %A", info);
  sprintf(buf, "from server : %s (%d:%d)", buf + 128, channel, port);
  memcpy(pBuf, buf, strlen(buf));
  return strlen(buf);
}

int onRecv(unsigned channel, int port, char* pBuf, unsigned size) {
  char buf[124];
  memset(buf, 0x00, sizeof(buf));
  memcpy(buf, pBuf, size);
  printf("from client : %s (%d:%d)\n", buf, channel, port);
  return 0;
}

void server(int flg) {
  Socket socket = {
      NULL,                               /* fd */
      0,         0, 1,     0, 0, 0, 0, 0, /* opt */
      // 1,         0, 1,     0, 0, 0, 0, 0, /* opt */
      "0.0.0.0", 0, 65000,                /* info */
  };
  InitSocket(&socket);
  SetSSLOption(&socket, SSLVER, _SSLV23);
  // SetSSLOption(&socket, SSLVER, _DTLSV12);
  SetSSLOption(&socket, VERIFY, _SSL_CA_FILE | _SSL_VER_PEER, "CA"SEP"ca.crt");
  SetSSLOption(&socket, CERTFILE, PEM, "CA"SEP"server.crt", "CA"SEP"server.key", NULL);
  SocketBind(&socket, onRecv, onSend);

  getchar();
  //   svr->load_cert_file(svr, _SSLV23_SERVER,
  //                       _SSL_CA_FILE | _SSL_SVR_VER_PEER_UPPER, 0, 3,
  //                       "CA\\ca.crt", "CA\\server.key", "CA\\server.crt");
  //   svr->listen(svr);
}

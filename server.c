#define _SOCKET_SERVER
#include "socket/socket.h"

SSL* handle(socket_function *fun, SOCKET fd, SSL *ssl) {
  int err;
  char buf[1024];
  memset(buf, 0x00, sizeof(buf));
RetryR:
  if (ssl) {
    err = SSL_read(ssl, buf, 1024);
  } else {
    err = recv(fd, buf, 1024, 0);
  }
  if (err < 0) {
    goto RetryR;
  }
RetryW:
  if (ssl) {
    err = SSL_write(ssl, buf, strlen(buf));
  } else {
    err = send(fd, buf, strlen(buf), 0);
  }
  if (err < 0) {
    goto RetryW;
  }
  return 0;
}

void server(int flg) {
  socket_option opt = {
      0, 0, 0, 0, 1, 0, 0, 0, 0, 65000, "0.0.0.0",
  };

  char *msg = 0;
  if (flg == 1) msg = "hello, client!";

  socket_function *svr = initServer(&opt, handle, msg);
  svr->load_cert_file(svr, "CA\\server.key", "CA\\server.crt", _SSLV23_SERVER,
                       0);
  svr->listen(svr);
}

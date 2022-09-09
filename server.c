#define _SOCKET_SERVER
#include "socket/socket.h"

int handle(SOCKET fd, SSL *ssl) {
  int err;
  char buf[1024];

	memset(buf, 0x00, sizeof(buf));
RetryR:
    err = recv(fd, buf, 1024, 0);
    if (err < 0) {
      goto RetryR;
    }
RetryW:
    err = send(fd, buf, strlen(buf), 0);
    if (err < 0) {
      goto RetryW;
    }
}

void server() {
  socket_option opt = {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 65000, "localhost",
  };

  char *msg = "hello, client!";

  socket_function *svr = initServer(&opt, handle, msg);

  svr->listen(svr);
}

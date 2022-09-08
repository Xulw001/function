#define _SOCKET_SERVER
#include "socket/socket.h"

int handle(SOCKET fd, SSL *ssl) {
  int err;
  char buf[1024] = {0};

  while (1) {
    err = recv(fd, buf, 1024, 0);
    if (err < 0) {
      continue;
    }
    err = send(fd, buf, 1024, 0);
    if (err < 0) {
      continue;
    }
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

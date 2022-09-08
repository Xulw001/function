#define _SOCKET_SERVER
#include "socket/socket.h"

int handle(SOCKET fd, SSL *ssl) {
  char buf[1024] = {0};

  while (1) {
    recv(fd, buf, 1024, 0);
    send(fd, buf, 1024, 0);
  }
}

void server() {
  socket_option opt = {
      0, 0, 0, 0, 0, 0, 0, 0, 10, 65000, "localhost",
  };

  char *msg = "hello, client!";

  socket_function *svr = initServer(&opt, handle, msg);

  svr->listen(svr);
}

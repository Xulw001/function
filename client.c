#include "socket/socket.h"

void client() {
  socket_option opt = {
      0, 0, 0, 0, 0, 0, 0, 0, 10, 65000, "localhost",
  };
  char buf[1024] = {0};
  socket_function *cli = initClient(&opt);

  cli->connect(cli);

  while (1) {
    cli->recv(cli, buf, 1024);
    printf("From server: %s\n", buf);
    memset(buf, 0x00, sizeof(buf));
    scanf("%[^\n]", buf);
    cli->send(cli, buf, strlen(buf));
    printf("To server: %s\n", buf);
    memset(buf, 0x00, sizeof(buf));
  }
}

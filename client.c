#include "socket/socket.h"

void client() {
  int err;
  char ch;
  socket_option opt = {
      0, 0, 0, 0, 0, 0, 0, 0, 3, 65000, "localhost",
  };
  char buf[1024] = {0};
  socket_function *cli = initClient(&opt);

  cli->connect(cli);

  while (1) {
    err = cli->recv(cli, buf, 1024);
    if (err == 0) continue;
    printf("From server: %s\n", buf);
    memset(buf, 0x00, sizeof(buf));
    scanf("%[^\n]", buf);
    if (memcmp(buf, "close", 6) == 0) break;
    scanf("%c", &ch);
    err = cli->send(cli, buf, strlen(buf));
    if (err == 0) continue;
    printf("To server: %s\n", buf);
    memset(buf, 0x00, sizeof(buf));
  }
  final(cli);
}

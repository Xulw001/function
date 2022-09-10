#include "socket/socket.h"

void client(int flg) {
  int err;
  char ch;
  socket_option opt = {
      0, 0, 0, 0, 1, 0, 0, 0, 3, 65000, "192.168.31.1",
  };
  char buf[1024] = {0};
  socket_function *cli = initClient(&opt);

  cli->connect(cli);

  while (1) {
    if (flg == 1) {
      err = cli->recv(cli, buf, 1024);
      if (err == SOCKET_CLOSE) break;
      if (err == 0) continue;
      printf("From server: %s\n", buf);
    }
    memset(buf, 0x00, sizeof(buf));
NEXT:
    scanf("%[^\n]", buf);
    scanf("%c", &ch);
    if(strlen(buf) == 0) goto NEXT;
    if (memcmp(buf, "close", 6) == 0) break;
    err = cli->send(cli, buf, strlen(buf));
    if (err == SOCKET_CLOSE || err == SOCKET_DOWN) break;
    if (err == 0) continue;
    printf("To server: %s\n", buf);
    memset(buf, 0x00, sizeof(buf));
    if (flg == 0) {
      err = cli->recv(cli, buf, 1024);
      if (err == SOCKET_CLOSE || err == SOCKET_DOWN) break;
      if (err == 0) continue;
      printf("From server: %s\n", buf);
    }
  }
  final(cli);
  printf("%d\n", err);
}

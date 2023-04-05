#include <stdio.h>
#include <time.h>

#include "socket/socket.h"
#ifndef _WIN32
#include <arpa/inet.h>
#define SEP "/"
#else
#define SEP "\\"
#endif

void client(int flg) {
  Socket socket = {
      NULL,                                 /* fd */
      0,           1, 1,     0, 0, 0, 0, 0, /* opt */
      "192.168.31.131", 0, 65000,                /* info */
  };
  InitSocket(&socket);
  SetSSLOption(&socket, SSLVER, _SSLV23);
  // SetSSLOption(&socket, SSLVER, _DTLSV12);
  SetSSLOption(&socket, VERIFY, _SSL_CA_FILE | _SSL_VER_PEER, "CA"SEP"ca.crt");
  SetSSLOption(&socket, CERTFILE, PEM, "CA"SEP"server.crt", "CA"SEP"server.key", NULL);
  char buf[1024] = {0};

  do {
    time_t ctime;
    struct tm* info;
    time(&ctime);
    info = localtime(&ctime);
    strftime(buf, 100, "%Y-%m-%d %H:%M:%S %A", info);
    SocketSend(&socket, buf, strlen(buf));
    if (SocketRecv(&socket, buf, 1024) == 0) {
      break;
    }
    printf("%s\n", buf);
    scanf("%s", buf);
    if (strcmp(buf, "quit") == 0) {
      break;
    }
    // time_t ctime;
    // struct tm* info;
    // time(&ctime);
    // info = localtime(&ctime);
    // strftime(buf, 100, "%Y-%m-%d %H:%M:%S %A", info);
    // SocketSend(&socket, buf, strlen(buf));
  } while (1);

  EndSocket(&socket);
  return;
}


void clientxx(int flg) {
  char buf[1024] = {0};
  Socket ss;
  InitSocket(&ss);
    //udp
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof local_addr);
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(64000);
    local_addr.sin_addr.s_addr = inet_addr("192.168.229.1");
    int r = bind(fd, (struct sockaddr *) &local_addr, sizeof(struct sockaddr));
// printf("%d\n", GetLastError());
    struct sockaddr_in other_addr;
	memset(&other_addr, 0, sizeof other_addr);
	other_addr.sin_family = AF_INET;
	other_addr.sin_port = htons(65000);
	other_addr.sin_addr.s_addr = inet_addr("192.168.229.1");

  connect(fd, (struct sockaddr *) &other_addr, sizeof(struct sockaddr));

  printf("%d\n", __errno());

	int i = 2;
    while(1){

    time_t ctime;
    struct tm* info;
    time(&ctime);
    info = localtime(&ctime);
    strftime(buf, 100, "%Y-%m-%d %H:%M:%S %A", info);

    	int r = sendto(fd,buf,strlen(buf),0, (struct sockaddr *) &other_addr, sizeof(other_addr));
printf("%d\n", __errno());

    	socklen_t rsz = sizeof(other_addr);
    	int recv_sive = recvfrom(fd,buf,sizeof(buf),0, (struct sockaddr *) &other_addr, &rsz);
    	printf("%s\n", buf);
    }
    Close(fd);
    return ;
}

// void client(int flg) {
//   int err;
//   char ch;
//   socket_option opt = {
//       0, 0, 0, 1, 0, 0, 0, 0, 3, 65000, "192.168.31.1",
//   };
//   char buf[1024] = {0};
//   socket_function *cli = initClient(&opt);

//   cli->load_cert_file(cli, _SSLV23_CLIENT, _SSL_CA_FILE | _SSL_CLI_VER_PEER,
//   0,
//                       3, "CA\\ca.crt", "CA\\server.key", "CA\\server.crt");

//   cli->connect(cli);

//   while (1) {
//     if (flg == 1) {
//       err = cli->recv(cli, buf, 1024);
//       if (err == SOCKET_CLOSE) break;
//       if (err == 0) continue;
//       printf("From server: %s\n", buf);
//     }
//     memset(buf, 0x00, sizeof(buf));
//   NEXT:
//     scanf("%[^\n]", buf);
//     scanf("%c", &ch);
//     if (strlen(buf) == 0) goto NEXT;
//     if (memcmp(buf, "close", 6) == 0) break;
//     err = cli->send(cli, buf, strlen(buf));
//     if (err == SOCKET_CLOSE || err == SOCKET_DOWN) break;
//     if (err == 0) continue;
//     printf("To server: %s\n", buf);
//     memset(buf, 0x00, sizeof(buf));
//     if (flg == 0) {
//       err = cli->recv(cli, buf, 1024);
//       if (err == SOCKET_CLOSE || err == SOCKET_DOWN) break;
//       if (err == 0) continue;
//       printf("From server: %s\n", buf);
//     }
//   }
//   final(cli);
//   printf("%d\n", err);
// }

1.����openssl����
set OPENSSL_CONF=D:\source\openssl-openssl-3.0.1\openssl\ssl\openssl.cnf
set PATH=D:\source\openssl-openssl-3.0.1\openssl\bin;%PATH%
2.����SSL֤��
1)��׼����
##���ɸ�CA˽Կ
openssl genrsa -out ca.key 2048
##����CA��֤��
openssl req -new -x509 -days 3652 -key ca.key -out ca.crt -subj "/C=CN/ST=JS/L=NJ/O=MySocket/OU=SOCKET/CN=localhost"

##����SSL֤��˽Կ
openssl genrsa -out server.pem 2048
##����SSL֤�鹫Կ
openssl rsa -in server.pem -out server.key
##����SSL֤������
openssl req -new -key server.pem -out server.csr -subj "/C=CN/ST=JS/L=NJ/O=MySocket/OU=SOCKET/CN=localhost"
##��CA����SSL֤��ǩ��
openssl ca -policy policy_anything -days 3652 -cert ca.crt -keyfile ca.key -in server.csr -out server.crt
2)��������
openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes

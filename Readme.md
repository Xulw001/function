1.设置openssl配置
set OPENSSL_CONF=D:\source\openssl-openssl-3.0.1\openssl\ssl\openssl.cnf
set PATH=D:\source\openssl-openssl-3.0.1\openssl\bin;%PATH%
2.生成SSL证书
1)标准流程
##生成根CA私钥
openssl genrsa -out ca.key 2048
##生成CA根证书
openssl req -new -x509 -days 3652 -key ca.key -out ca.crt -subj "/C=CN/ST=JS/L=NJ/O=MySocket/OU=SOCKET/CN=localhost"

##生成SSL证书私钥
openssl genrsa -out server.pem 2048
##制作SSL证书公钥
openssl rsa -in server.pem -out server.key
##生成SSL证书请求
openssl req -new -key server.pem -out server.csr -subj "/C=CN/ST=JS/L=NJ/O=MySocket/OU=SOCKET/CN=localhost"
##根CA进行SSL证书签发
openssl ca -policy policy_anything -days 3652 -cert ca.crt -keyfile ca.key -in server.csr -out server.crt
2)简易流程
openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes

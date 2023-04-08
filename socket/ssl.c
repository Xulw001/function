#include "ssl.h"
#define COOKIE_SECRET_LENGTH 16
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
unsigned cookie_initialized = 0;

int InitSSL(Socket* pSocket) {
#ifdef _WIN32
  while (RAND_status() == 0)
    ;
#endif
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  return 0;
}

int SslErr(char* file, int line, int err, char* fun) {
  unsigned long ulErr = 0;
  char* pTmp = NULL;
  char msg[1024];
  memset(msg, 0x00, sizeof(msg));
  ulErr = ERR_get_error();
  pTmp = (char*)ERR_reason_error_string(ulErr);
  if (pTmp) strncpy(msg, pTmp, 1024);
  ERR_free_strings();
#ifdef _TEST_DEBUG
  printf("error appear at %s:%d in %s, errno = %d, msg = %s\n", file, line, fun,
         err, msg);
#endif
  return -1;
}

int SslCheck(SSL* ssl, int ret) {
  int err = SSL_get_error(ssl, ret);
  switch (err) {
    case SSL_ERROR_NONE:         // ok
    case SSL_ERROR_ZERO_RETURN:  // close
      return 0;
    case SSL_ERROR_WANT_READ:     // read again
    case SSL_ERROR_WANT_WRITE:    // write again
    case SSL_ERROR_WANT_ACCEPT:   // accept again
    case SSL_ERROR_WANT_CONNECT:  // connect again
      return 1;
    default:
      return -1;
  }
}

int InitSSLSocket(Socket* pSocket, int flag) {
  int err = 0;
  ssl_channel* pssl = NULL;
  int noCAfile = 0;
  int vpmtouched = 0;
  int filev = pSocket->sslInfo.filever;
  char* CAfile = pSocket->sslInfo.cCAFile;
  char* CApath = pSocket->sslInfo.cCAPath;
  char* cert_file = pSocket->sslInfo.certfile;
  char* key_file = pSocket->sslInfo.keyfile;
  char* key_passwd = pSocket->sslInfo.keypass;
  SSL_EXTEND_OPT* opt = pSocket->sslInfo.opt;
  int verifypeer = 0;
  const SSL_METHOD* meth;
  X509_VERIFY_PARAM* vpm = NULL;

  pssl = (ssl_channel*)malloc(sizeof(ssl_channel));
  if (pssl == 0) {
    ERROUT("malloc", __errno());
    return -1;
  }

  InitSSL(pSocket);
  switch (pSocket->sslInfo.ver) {
    case _SSLV23:
    case _TLSV1:
    case _TLSV11:
    case _TLSV12:
      if (pSocket->opt.udp_flg) {
        ERROUT("ssl version not support", -1);
        return -1;
      }
      if (flag) {
        meth = SSLv23_client_method();
      } else {
        meth = SSLv23_server_method();
      }
      break;
    case _DTLS:
    case _DTLSV1:
    case _DTLSV12:
#ifdef _WIN32
      ERROUT("DTLS Not Work On Windows", -1);
      return -1;
#endif
#ifdef OPENSSL_NO_SOCK
      ERROUT("UDP Not Support With Openssl Library", -1);
      return -1;
#endif
      if (!pSocket->opt.udp_flg) {
        ERROUT("ssl version not support", -1);
        return -1;
      }
      if (flag) {
        meth = DTLS_client_method();
      } else {
        meth = DTLS_server_method();
      }
      break;
  }

  pssl->ctx = SSL_CTX_new(meth);
  if (pssl->ctx == NULL)
    return SslErr(__FILE__, __LINE__, __errno(), "SSL_CTX_new");

  vpm = X509_VERIFY_PARAM_new();
  if (vpm == NULL)
    return SslErr(__FILE__, __LINE__, __errno(), "X509_VERIFY_PARAM_new");

  long ctx_options = SSL_OP_ALL;
  ctx_options |= SSL_OP_NO_TICKET;
  ctx_options |= SSL_OP_NO_COMPRESSION;
  ctx_options &= ~SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG;
  ctx_options &= ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
  ctx_options |= SSL_OP_NO_SSLv2;
  ctx_options |= SSL_OP_NO_SSLv3;

  SSL_CTX_set_max_proto_version(pssl->ctx, 0);
  SSL_CTX_set_options(pssl->ctx, ctx_options);

  if (opt != NULL) {
    if (OptVerify(opt, vpm)) {
      return -1;
    }
    vpmtouched = 1;
  }

  if (vpmtouched && !SSL_CTX_set1_param(pssl->ctx, vpm)) {
    return SslErr(__FILE__, __LINE__, __errno(), "SSL_CTX_set1_param");
  }

  if (cert_file) {
    if (key_passwd) {
      SSL_CTX_set_default_passwd_cb_userdata(pssl->ctx, key_passwd);
    }

    switch (filev) {
      case SSL_FILETYPE_PEM:
        if (!SSL_CTX_use_certificate_chain_file(pssl->ctx, cert_file))
          return SslErr(__FILE__, __LINE__, __errno(),
                        "SSL_CTX_use_certificate_chain_file");
        break;
      case SSL_FILETYPE_ASN1:
        if (!SSL_CTX_use_certificate_file(pssl->ctx, cert_file, filev))
          return SslErr(__FILE__, __LINE__, __errno(),
                        "SSL_CTX_use_certificate_file");
        break;
      default:
        break;
    }

    if (!key_file) key_file = cert_file;

    if (!SSL_CTX_use_PrivateKey_file(pssl->ctx, key_file, filev))
      return SslErr(__FILE__, __LINE__, __errno(),
                    "SSL_CTX_use_PrivateKey_file");

    if (!SSL_CTX_check_private_key(pssl->ctx))
      return SslErr(__FILE__, __LINE__, __errno(), "SSL_CTX_check_private_key");
  }

  if (_SSL_CA_NO != pSocket->sslInfo.caopt) {
    switch (pSocket->sslInfo.caopt) {
      case _SSL_CA_NATVE: {
#ifdef USE_WIN32_CRYPTO
        X509_STORE* store = SSL_CTX_get_cert_store(pssl->ctx);
        HCERTSTORE hStore = CertOpenSystemStore(0, TEXT("ROOT"));

        if (hStore) {
          PCCERT_CONTEXT pContext = NULL;
          CERT_ENHKEY_USAGE* enhkey_usage = NULL;
          DWORD enhkey_usage_size = 0;

          for (;;) {
            X509* x509;
            FILETIME now;
            BYTE key_usage[2];
            DWORD req_size;
            const unsigned char* encoded_cert;

            pContext = CertEnumCertificatesInStore(hStore, pContext);
            if (!pContext) break;

            // A pointer to a buffer that contains the encoded certificate
            encoded_cert = (const unsigned char*)pContext->pbCertEncoded;
            if (!encoded_cert) continue;

            // judge whether the certificate time
            GetSystemTimeAsFileTime(&now);
            if (CompareFileTime(&pContext->pCertInfo->NotBefore, &now) > 0 ||
                CompareFileTime(&now, &pContext->pCertInfo->NotAfter) > 0)
              continue;

            /* If key usage exists check for signing attribute */
            if (CertGetIntendedKeyUsage(pContext->dwCertEncodingType,
                                        pContext->pCertInfo, key_usage,
                                        sizeof(key_usage))) {
              if (!(key_usage[0] & CERT_KEY_CERT_SIGN_KEY_USAGE)) continue;
            } else if (GetLastError())
              continue;

            /* If enhanced key usage exists check for server auth attribute.
             *
             * Note "In a Microsoft environment, a certificate might also have
             * EKU extended properties that specify valid uses for the
             * certificate." The call below checks both, and behavior varies
             * depending on what is found. For more details see
             * CertGetEnhancedKeyUsage doc.
             */
            if (CertGetEnhancedKeyUsage(pContext, 0, NULL, &req_size)) {
              if (req_size && req_size > enhkey_usage_size) {
                void* tmp = realloc(enhkey_usage, req_size);

                if (!tmp) {
                  ERROUT("realloc", GetLastError());
                  err = -1;
                  break;
                }

                enhkey_usage = (CERT_ENHKEY_USAGE*)tmp;
                enhkey_usage_size = req_size;
              }

              if (CertGetEnhancedKeyUsage(pContext, 0, enhkey_usage,
                                          &req_size)) {
                if (!enhkey_usage->cUsageIdentifier) {
                  /* "If GetLastError returns CRYPT_E_NOT_FOUND, the certificate
                     is good for all uses. If it returns zero, the certificate
                     has no valid uses." */
                  if ((HRESULT)GetLastError() != CRYPT_E_NOT_FOUND) continue;
                } else {
                  DWORD i;
                  int found = 0;

                  for (i = 0; i < enhkey_usage->cUsageIdentifier; ++i) {
                    if (!strcmp("1.3.6.1.5.5.7.3.1" /* OID server auth */,
                                enhkey_usage->rgpszUsageIdentifier[i])) {
                      found = 1;
                      break;
                    }
                  }

                  if (!found) continue;
                }
              } else
                continue;
            } else
              continue;

            x509 = d2i_X509(NULL, &encoded_cert, pContext->cbCertEncoded);
            if (!x509) continue;

            /* Try to import the certificate. This may fail for legitimate
               reasons such as duplicate certificate, which is allowed by MS but
               not OpenSSL. */
            if (X509_STORE_add_cert(store, x509) != 1) {
              SslErr(__FILE__, __LINE__, __errno(), "X509_STORE_add_cert");
              err = -1;
              break;
            }
            X509_free(x509);
          }

          free(enhkey_usage);
          CertFreeCertificateContext(pContext);
          CertCloseStore(hStore, 0);

          if (err) return err;
        }
#endif
      } break;
      case _SSL_CA_DEFAULT:
        SSL_CTX_set_default_verify_paths(pssl->ctx);
        break;
      default: {
#ifdef _OPENSSL_V3
        if (CAfile && !SSL_CTX_load_verify_file(pssl->ctx, CAfile))
          /* Fail if we insist on successfully verifying the server. */
          return SslErr(__FILE__, __LINE__, __errno(),
                        "SSL_CTX_load_verify_file");

        if (CApath && !SSL_CTX_load_verify_dir(pssl->ctx, CApath))
          /* Fail if we insist on successfully verifying the server. */
          return SslErr(__FILE__, __LINE__, __errno(),
                        "SSL_CTX_load_verify_dir");
#else
        if ((CAfile || CApath) &&
            !SSL_CTX_load_verify_locations(pssl->ctx, CAfile, CApath))
          /* Fail if we insist on successfully verifying the server. */
          return SslErr(__FILE__, __LINE__, __errno(),
                        "SSL_CTX_load_verify_locations");
#endif
      } break;
    }
    X509_STORE_set_flags(SSL_CTX_get_cert_store(pssl->ctx),
                         X509_V_FLAG_TRUSTED_FIRST);
    X509_STORE_set_flags(SSL_CTX_get_cert_store(pssl->ctx),
                         X509_V_FLAG_PARTIAL_CHAIN);
  }

  switch (pSocket->sslInfo.verify) {
    case _SSL_VER_NONE:
      verifypeer = SSL_VERIFY_NONE;
      break;
    case _SSL_VER_PEER:
      if (flag) {
        verifypeer = SSL_VERIFY_PEER;
      } else {
        verifypeer = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
      }
      break;
    case _SSL_VER_PEER_UPPER:
      if (flag) {
        verifypeer = SSL_VERIFY_PEER;
      } else {
        verifypeer = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT |
                     SSL_VERIFY_CLIENT_ONCE;
      }
      break;
  }

  if (pSocket->opt.udp_flg) {
    SSL_CTX_set_cookie_generate_cb(pssl->ctx, GenerateCookie);
    SSL_CTX_set_cookie_verify_cb(pssl->ctx, VerifyCookie);
  }

  SSL_CTX_set_read_ahead(pssl->ctx, 1);
  SSL_CTX_set_verify(pssl->ctx, verifypeer, NULL);

  if (flag) {
    SSL_CTX_set_post_handshake_auth(pssl->ctx, 1);
    SSL_CTX_set_session_cache_mode(
        pssl->ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
  } else {
    SSL_CTX_set_session_cache_mode(pssl->ctx, SSL_SESS_CACHE_NO_AUTO_CLEAR);
  }

  pSocket->fd = pssl;
  return 0;
}

int VerifyCookie(SSL* ssl, const unsigned char* cookie,
                 unsigned int cookie_len) {
  unsigned char *buffer, result[EVP_MAX_MD_SIZE];
  unsigned int length = 0, resultlength;
  sockaddr_info peer;

  /* If secret isn't initialized yet, the cookie can't be valid */
  if (!cookie_initialized) return 0;

  /* Read peer information */
  (void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

  /* Create buffer with peer's address and port */
  length = 0;
  switch (peer.ss.ss_family) {
    case AF_INET:
      length += sizeof(struct in_addr);
      break;
    case AF_INET6:
      length += sizeof(struct in6_addr);
      break;
    default:
      OPENSSL_assert(0);
      break;
  }
  length += sizeof(u_short);
  buffer = (unsigned char*)OPENSSL_malloc(length);

  if (buffer == NULL) {
    printf("out of memory\n");
    return 0;
  }

  switch (peer.ss.ss_family) {
    case AF_INET:
      memcpy(buffer, &peer.v4.sin_port, sizeof(u_short));
      memcpy(buffer + sizeof(u_short), &peer.v4.sin_addr,
             sizeof(struct in_addr));
      break;
    case AF_INET6:
      memcpy(buffer, &peer.v6.sin6_port, sizeof(u_short));
      memcpy(buffer + sizeof(u_short), &peer.v6.sin6_addr,
             sizeof(struct in6_addr));
      break;
    default:
      OPENSSL_assert(0);
      break;
  }

  /* Calculate HMAC of buffer using the secret */
  HMAC(EVP_sha1(), (const void*)cookie_secret, COOKIE_SECRET_LENGTH,
       (const unsigned char*)buffer, length, result, &resultlength);
  OPENSSL_free(buffer);

  if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
    return 1;

  return 0;
}

int GenerateCookie(SSL* ssl, unsigned char* cookie, unsigned int* cookie_len) {
  unsigned char *buffer, result[EVP_MAX_MD_SIZE];
  unsigned length = 0, resultlength;
  sockaddr_info peer;

  /* Initialize a random secret */
  if (!cookie_initialized) {
    if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH)) {
      printf("error setting random cookie secret\n");
      return 0;
    }
    cookie_initialized = 1;
  }

  /* Read peer information */
  (void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

  /* Create buffer with peer's address and port */
  length = 0;
  switch (peer.ss.ss_family) {
    case AF_INET:
      length += sizeof(struct in_addr);
      break;
    case AF_INET6:
      length += sizeof(struct in6_addr);
      break;
    default:
      OPENSSL_assert(0);
      break;
  }
  length += sizeof(u_short);
  buffer = (unsigned char*)OPENSSL_malloc(length);

  if (buffer == NULL) {
    printf("out of memory\n");
    return 0;
  }

  switch (peer.ss.ss_family) {
    case AF_INET:
      memcpy(buffer, &peer.v4.sin_port, sizeof(u_short));
      memcpy(buffer + sizeof(peer.v4.sin_port), &peer.v4.sin_addr,
             sizeof(struct in_addr));
      break;
    case AF_INET6:
      memcpy(buffer, &peer.v6.sin6_port, sizeof(u_short));
      memcpy(buffer + sizeof(u_short), &peer.v6.sin6_addr,
             sizeof(struct in6_addr));
      break;
    default:
      OPENSSL_assert(0);
      break;
  }

  /* Calculate HMAC of buffer using the secret */
  HMAC(EVP_sha1(), (const void*)cookie_secret, COOKIE_SECRET_LENGTH,
       (const unsigned char*)buffer, length, result, &resultlength);
  OPENSSL_free(buffer);

  memcpy(cookie, result, resultlength);
  *cookie_len = resultlength;

  return 1;
}

int OptVerify(SSL_EXTEND_OPT* opt, X509_VERIFY_PARAM* vpm) {
  int i;
  ossl_intmax_t t = 0;
  ASN1_OBJECT* otmp;
  X509_PURPOSE* xptmp;
  const X509_VERIFY_PARAM* vtmp;

  if (opt->OPT_V_POLICY) {
    otmp = OBJ_txt2obj(opt->OPT_V_POLICY, 0);
    if (otmp == NULL)
      return SslErr(__FILE__, __LINE__, __errno(), "OBJ_txt2obj");
    X509_VERIFY_PARAM_add0_policy(vpm, otmp);
  }
  if (opt->OPT_V_PURPOSE) {
    /* purpose name -> purpose index */
    i = X509_PURPOSE_get_by_sname(opt->OPT_V_PURPOSE);
    if (i < 0)
      return SslErr(__FILE__, __LINE__, __errno(), "X509_PURPOSE_get_by_sname");
    /* purpose index -> purpose object */
    xptmp = X509_PURPOSE_get0(i);
    /* purpose object -> purpose value */
    i = X509_PURPOSE_get_id(xptmp);
    if (!X509_VERIFY_PARAM_set_purpose(vpm, i))
      return SslErr(__FILE__, __LINE__, __errno(),
                    "X509_VERIFY_PARAM_set_purpose");
  }
  if (opt->OPT_V_VERIFY_NAME) {
    vtmp = X509_VERIFY_PARAM_lookup(opt->OPT_V_VERIFY_NAME);
    if (vtmp == NULL)
      return SslErr(__FILE__, __LINE__, __errno(), "X509_VERIFY_PARAM_lookup");

    X509_VERIFY_PARAM_set1(vpm, vtmp);
  }
  if (opt->OPT_V_VERIFY_DEPTH) {
    X509_VERIFY_PARAM_set_depth(vpm, opt->OPT_V_VERIFY_DEPTH);
  }
  if (opt->OPT_V_VERIFY_AUTH_LEVEL) {
    X509_VERIFY_PARAM_set_auth_level(vpm, opt->OPT_V_VERIFY_AUTH_LEVEL);
  }
  if (opt->OPT_V_ATTIME) {
    WARNING("opt_verify cause by OPT_V_ATTIME not support");
  }
  if (opt->OPT_V_VERIFY_HOSTNAME) {
    if (!X509_VERIFY_PARAM_set1_host(vpm, opt->OPT_V_VERIFY_HOSTNAME, 0))
      return SslErr(__FILE__, __LINE__, __errno(),
                    "X509_VERIFY_PARAM_set1_host");
  }
  if (opt->OPT_V_VERIFY_EMAIL) {
    if (!X509_VERIFY_PARAM_set1_email(vpm, opt->OPT_V_VERIFY_EMAIL, 0))
      return SslErr(__FILE__, __LINE__, __errno(),
                    "X509_VERIFY_PARAM_set1_email");
  }
  if (opt->OPT_V_VERIFY_IP) {
    if (!X509_VERIFY_PARAM_set1_ip_asc(vpm, opt->OPT_V_VERIFY_IP))
      return SslErr(__FILE__, __LINE__, __errno(),
                    "X509_VERIFY_PARAM_set1_ip_asc");
  }
  if (opt->OPT_V_IGNORE_CRITICAL) {
    X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_IGNORE_CRITICAL);
  }
  if (opt->OPT_V_ISSUER_CHECKS) {
    ; /* NOP, deprecated */
  }
  if (opt->OPT_V_CRL_CHECK) {
    X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_CRL_CHECK);
  }
  if (opt->OPT_V_CRL_CHECK_ALL) {
    X509_VERIFY_PARAM_set_flags(
        vpm, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
  }
  if (opt->OPT_V_POLICY_CHECK) {
    X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_POLICY_CHECK);
  }
  if (opt->OPT_V_EXPLICIT_POLICY) {
    X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_EXPLICIT_POLICY);
  }
  if (opt->OPT_V_INHIBIT_ANY) {
    X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_INHIBIT_ANY);
  }
  if (opt->OPT_V_INHIBIT_MAP) {
    X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_INHIBIT_MAP);
  }
  if (opt->OPT_V_X509_STRICT) {
    X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_X509_STRICT);
  }
  if (opt->OPT_V_EXTENDED_CRL) {
    X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_EXTENDED_CRL_SUPPORT);
  }
  if (opt->OPT_V_USE_DELTAS) {
    X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_USE_DELTAS);
  }
  if (opt->OPT_V_POLICY_PRINT) {
    X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_NOTIFY_POLICY);
  }
  if (opt->OPT_V_CHECK_SS_SIG) {
    X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_CHECK_SS_SIGNATURE);
  }
  if (opt->OPT_V_TRUSTED_FIRST) {
    X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_TRUSTED_FIRST);
  }
  if (opt->OPT_V_SUITEB_128_ONLY) {
    X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_SUITEB_128_LOS_ONLY);
  }
  if (opt->OPT_V_SUITEB_128) {
    X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_SUITEB_128_LOS);
  }
  if (opt->OPT_V_SUITEB_192) {
    X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_SUITEB_192_LOS);
  }
  if (opt->OPT_V_PARTIAL_CHAIN) {
    X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_PARTIAL_CHAIN);
  }
  if (opt->OPT_V_NO_ALT_CHAINS) {
    X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_NO_ALT_CHAINS);
  }
  if (opt->OPT_V_NO_CHECK_TIME) {
    X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_NO_CHECK_TIME);
  }
  if (opt->OPT_V_ALLOW_PROXY_CERTS) {
    X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_ALLOW_PROXY_CERTS);
  }
  return 0;
}
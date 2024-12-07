#include <import>

#define Session_schema(X,Y) \
    i_prop    (X,Y, public,  TLS,      tls) \
    i_prop    (X,Y, intern,  raw_t,    fd) \
    i_prop    (X,Y, intern,  raw_t,    ssl) \
    i_prop    (X,Y, public,  bool,     connected) \
    i_prop    (X,Y, public,  num,      timeout_ms) \
    i_method  (X,Y, public,  none,     init_accept,  TLS) \
    i_method  (X,Y, public,  none,     init_connect, uri) \
    i_method  (X,Y, public,  bool,     bind,        uri) \
    i_method  (X,Y, public,  bool,     connect) \
    i_method  (X,Y, public,  bool,     close) \
    i_method  (X,Y, public,  none,     set_timeout, i64) \
    i_method  (X,Y, public,  bool,     read_sz,     raw_t, sz) \
    i_method  (X,Y, public,  sz,       recv,        raw_t, sz) \
    i_method  (X,Y, public,  sz,       send,        raw_t, sz) \
    i_method  (X,Y, public,  sz,       send_str,    string, array) \
    i_method  (X,Y, public,  sz,       send_object, object) \
    i_method  (X,Y, public,  vector,   read_until,  string, i32) \
    s_method  (X,Y, public,  sock,     accept,      TLS)
declare_class(Session)

// Implementation example:
none Session_init_accept(Session s, TLS tls) {
    mbedtls_ssl_init(s->ssl);
    mbedtls_net_init(s->fd);
    mbedtls_ssl_setup(s->ssl, tls->conf);
}

none Session_init_connect(Session s, uri addr) {
    s->tls = new(TLS, addr); 
}

bool Session_bind(Session s, uri addr) {
    string s_port = str(cast(num, addr->port));
    i32 res = mbedtls_net_bind(s->fd, addr->host->chars, s_port->chars, MBEDTLS_NET_PROTO_TCP);
    if (res != 0) {
        print("mbedtls_net_bind: fails with %i", res);
        return false;
    }
    return true;
}

bool Session_connect(Session s) {
    string host = s->tls->url->host;
    i32 port = s->tls->url->port;
    
    i32 ret = mbedtls_ssl_setup(s->ssl, s->tls->conf);
    if (ret != 0) {
        error("mbedtls_ssl_setup failed: %i", ret);
        return false;
    }

    string str_port = str(port);
    ret = mbedtls_ssl_set_hostname(s->ssl, host->chars);
    if (ret != 0) {
        error("mbedtls_ssl_set_hostname failed: %i", ret);
        return false;
    }
    
    ret = mbedtls_net_connect(s->fd, host->chars, str_port->chars, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        error("mbedtls_net_connect failed: %i", ret);
        return false;
    }
    
    mbedtls_ssl_set_bio(s->ssl, s->fd, mbedtls_net_send, mbedtls_net_recv, null);
    
    while ((ret = mbedtls_ssl_handshake(s->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            error("mbedtls_ssl_handshake failed: %i", ret);
            return false;
        }
    }
    s->connected = true;
    return true;
}
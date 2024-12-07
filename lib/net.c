
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <winsock2.h>
#include <windows.h>
#endif

//#include <mbedtls/build_info.h>

#include <mbedtls/platform.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
//#include "test/certs.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include <mbedtls/ssl_cache.h>
#endif

#ifndef WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <mbedtls/mbedtls_config.h> /// always must include first!
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>


#include <import>



define_class(Session)

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

bool Session_close(Session s) {
    i32 ret;
    while ((ret = mbedtls_ssl_close_notify(s->ssl)) < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && 
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            print("mbedtls_ssl_close_notify returned %i", ret);
            return false;
        }
    }
    return true;
}

none Session_set_timeout(Session s, i64 t) {
    s->timeout_ms = t;
}

bool Session_read_sz(Session s, handle v, sz sz) {
    i32 st = 0;
    for (i32 len = sz; len > 0;) {
        i32 rcv = mbedtls_ssl_read(s->ssl, v + st, len);
        if (rcv <= 0)
            return false;
        len -= rcv;
        st  += rcv;
    }
    return true;
}

sz Session_recv(Session s, handle buf, sz len) {
    sz sz;
    do {
        sz = mbedtls_ssl_read(s->ssl, buf, len);
        if (sz == MBEDTLS_ERR_SSL_WANT_READ || sz == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        break;
    } while(1);
    return sz;
}

sz Session_send(Session s, handle buf, sz len) {
    sz ret;
    while ((ret = mbedtls_ssl_write(s->ssl, buf, len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET)
            return 0;
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            break;
    }
    return ret;
}

sz Session_send_str(Session s, string templ, array args) {
    string val = format(templ->chars, args);
    return send(s, val->chars, len(val));
}

sz Session_send_object(Session s, object v) {
    return send(s, data(v), cast(sz, len(v)));
}

vector Session_read_until(Session s, string match, i32 max_len) {
    vector rbytes = new(vector);
    sz slen = len(match);
    
    for (;;) {
        push(rbytes, 0);
        sz sz = len(rbytes);
        if (!recv(s, &((char*)data(rbytes))[sz - 1], 1))
            return null;
            
        if (sz >= slen && 
            memcmp(&((char*)data(rbytes))[sz - slen], match->chars, slen) == 0)
            break;
            
        if (sz == max_len)
            return null;
    }
    return rbytes;
}

sock Session_accept(TLS tls) {
    sock client = new(sock);
    init_accept(client, tls);
    
    for (;;) {
        mbedtls_net_init(client->fd);
        mbedtls_ssl_setup(client->ssl, client->tls->conf);

        i32 ret;
        if ((ret = mbedtls_net_accept(tls->fd, client->fd, null, 0, null)) != 0) {
            return null;
        }
        mbedtls_ssl_session_reset(client->ssl);
        
        bool retry = false;
        mbedtls_ssl_set_bio(client->ssl, client->fd, 
                           mbedtls_net_send, mbedtls_net_recv, null);
        while ((ret = mbedtls_ssl_handshake(client->ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && 
                ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                print("mbedtls_ssl_handshake: %i", ret);
                retry = true;
                break;
            }
        }
        if (!retry)
            break;
    }
    client->connected = true;
    return client;
}

// First, all the declarations:

#define iTLS_schema(X,Y) \
    i_prop    (X,Y, intern, handle,    fd) \
    i_prop    (X,Y, intern, handle,    entropy) \
    i_prop    (X,Y, intern, handle,    ctr_drbg) \
    i_prop    (X,Y, intern, handle,    conf) \
    i_prop    (X,Y, intern, handle,    srvcert) \
    i_prop    (X,Y, intern, handle,    pkey) \
    i_prop    (X,Y, public,  uri,     url) \
    i_method  (X,Y, public,  none,    init, uri)
declare_class(iTLS)

#define message_schema(X,Y) \
    i_prop    (X,Y, public,  uri,     query) \
    i_prop    (X,Y, public,  i32,     code) \
    i_prop    (X,Y, public,  map,     headers) \
    i_prop    (X,Y, public,  object,  content) \
    i_method  (X,Y, public,  bool,    read_headers, sock) \
    i_method  (X,Y, public,  bool,    read_content, sock) \
    i_method  (X,Y, public,  bool,    write_status, sock) \
    i_method  (X,Y, public,  bool,    write_headers, sock) \
    i_method  (X,Y, public,  bool,    write, sock) \
    i_method  (X,Y, public,  string,  text) \
    i_method  (X,Y, public,  map,     cookies) \
    i_method  (X,Y, public,  object,  header, object) \
    s_method  (X,Y, public,  message, query, uri, map, object) \
    s_method  (X,Y, public,  message, response, uri, i32, object, map) \
    s_method  (X,Y, public,  symbol,  code_symbol, i32) \
    i_cast    (X,Y, public,  bool)
declare_class(message)

// Implementations:

none iTLS_init(iTLS tls, uri url) {
    tls->url = url;
    static bool init_done = false;
    if (!init_done) {
        #ifdef _WIN32
        WSADATA wsa_data;
        i32 wsa = WSAStartup(MAKEWORD(2,2), &wsa_data);
        if (wsa != 0) {
            print("(sock) WSAStartup failed: %i", wsa);
            return;
        }
        #endif
        init_done = true;
    }

    mbedtls_net_init(tls->fd);
    mbedtls_ssl_config_init(tls->conf);
    mbedtls_x509_crt_init(tls->srvcert);
    mbedtls_pk_init(tls->pkey);
    mbedtls_entropy_init(tls->entropy);
    mbedtls_ctr_drbg_init(tls->ctr_drbg);

    print("  . Seeding the random number generator...");

    i32 ret = mbedtls_ctr_drbg_seed(tls->ctr_drbg, mbedtls_entropy_func, tls->entropy,
                                   (handle)pers, strlen(pers));
    if (ret != 0) {
        print(" failed\n  ! mbedtls_ctr_drbg_seed returned %i", ret);
        return;
    }

    print(" ok\n");
    print("\n  . Loading the server cert. and key...");

    string host = url->host;
    string pub = format("ssl/%s.crt", host->chars);
    string prv = format("ssl/%s.key", host->chars);

    ret = mbedtls_x509_crt_parse_file(tls->srvcert, pub->chars);
    if (ret != 0) {
        print("mbedtls_x509_crt_parse returned %i\n", ret);
        return;
    }

    ret = mbedtls_pk_parse_keyfile(tls->pkey, prv->chars, 0, mbedtls_ctr_drbg_random, tls->ctr_drbg);
    if (ret != 0) {
        print("mbedtls_pk_parse_key returned %i\n", ret);
        return;
    }

    string port = str(url->port);
    ret = mbedtls_net_bind(tls->fd, host->chars, port->chars, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        print("mbedtls_net_bind returned %i\n", ret);
        return;
    }

    ret = mbedtls_ssl_config_defaults(tls->conf,
                                     MBEDTLS_SSL_IS_SERVER,
                                     MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        print("mbedtls_ssl_config_defaults returned %i\n", ret);
        return;
    }

    mbedtls_ssl_conf_rng(tls->conf, mbedtls_ctr_drbg_random, tls->ctr_drbg);
    mbedtls_ssl_conf_dbg(tls->conf, mbedtls_debug, stdout);
    mbedtls_ssl_conf_ca_chain(tls->conf, tls->srvcert->next, null);
    
    ret = mbedtls_ssl_conf_own_cert(tls->conf, tls->srvcert, tls->pkey);
    if (ret != 0) {
        print("mbedtls_ssl_conf_own_cert returned %i\n", ret);
        return;
    }
}

message message_with_server_code(message m, i32 code) {
    m->code = code;
    return m;
}

message message_with_text(message m, string text) {
    m->content = text;
    m->code = 200;
    return m;
}

message message_with_path(message m, path p, object modified_since) {
    verify(exists(p) == Exists_file, "path must exist");
    string content = cast(string, read(p, typeid(string)));
    m->content = content;
    string mime = format("text/plain"); // TODO: implement mime_type
    set(m->headers, str("Content-Type"), mime);
    m->code = 200;
    return m;
}

message message_with_content(message m, object content, map headers, uri query) {
    m->query = query;
    m->headers = headers;
    m->content = content;
    m->code = 200;
    return m;
}

bool message_read_headers(message m, sock sc) {
    i32 line = 0;
    for (;;) {
        vector rbytes = read_until(sc, str("\r\n"), 8192);
        sz sz = len(rbytes);
        if (sz == 0)
            return false;
        
        if (sz == 2)
            break;

        if (line++ == 0) {
            string hello = new(string, chars, data(rbytes), ref_length, sz - 2);
            array sp = split(hello, str(" "));
            
            // Handle response or request line
            if (len(hello) >= 12) {
                if (len(sp) >= 3) {
                    m->query = hello;
                    m->headers["Status"] = get(sp, 1);
                }
            }
        } else {
            for (sz i = 0; i < sz; i++) {
                if (((char*)data(rbytes))[i] == ':') {
                    string k = new(string, chars, data(rbytes), ref_length, i);
                    string v = new(string, chars, &((char*)data(rbytes))[i + 2], 
                                ref_length, sz - len(k) - 4);
                    set(m->headers, k, v);
                    break;
                }
            }
        }
    }
    return true;
}

bool message_read_content(message m, sock sc) {
    string te = str("Transfer-Encoding");
    string cl = str("Content-Length");
    string ce = str("Content-Encoding");
    
    string encoding = contains(m->headers, te) ? get(m->headers, ce) : null;
    i32 clen = contains(m->headers, cl) ? 
               cast(i32, get(m->headers, cl)) : -1;
    bool chunked = encoding && strcmp(get(m->headers, te), "chunked") == 0;
    num content_len = clen;
    num rlen = 0;
    const num r_max = 1024;
    bool error = false;
    num iter = 0;
    vector v_data = new(vector);

    verify(!(clen >= 0 && chunked), "invalid transfer encoding");

    if (!chunked && clen <= 0) {
        m->content = null;
        return true;
    }

    if (!(!chunked && clen == 0)) {
        do {
            if (chunked) {
                if (iter++ > 0) {
                    char crlf[2];
                    if (!read_sz(sc, crlf, 2) || memcmp(crlf, "\r\n", 2) != 0) {
                        error = true;
                        break;
                    }
                }
                vector rbytes = read_until(sc, str("\r\n"), 64);
                if (!rbytes) {
                    error = true;
                    break;
                }
                
                // Parse hex length
                content_len = strtol(data(rbytes), null, 16);
                if (content_len == 0)
                    break;
            }

            bool sff = content_len == -1;
            for (num rcv = 0; sff || rcv < content_len; rcv += rlen) {
                num rx = min(r_max, content_len - rcv);
                char buf[r_max];
                rlen = recv(sc, buf, rx);
                
                if (rlen > 0)
                    push(v_data, buf, rlen);
                else if (rlen < 0) {
                    error = !sff;
                    break;
                } else if (rlen == 0) {
                    error = true;
                    break;
                }
            }
        } while (!error && chunked && content_len != 0);
    }

    if (!error) {
        string ctype = contains(m->headers, "Content-Type") ? 
                      get(m->headers, str("Content-Type")) : null;

        if (ctype && starts_with(ctype, str("application/json"))) {
            if (encoding) {
                if (strcmp(encoding, "gzip") == 0) {
                    // TODO: implement inflate
                    v_data = null;
                }
            }
            
            // Parse JSON
            m->content = null; // TODO: implement JSON parsing
        } else if (ctype && starts_with(ctype, str("text/"))) {
            m->content = new(string, chars, data(v_data), ref_length, len(v_data));
        } else {
            verify(len(v_data) == 0, "unsupported content type");
            m->content = null;
        }
    }

    return !error;
}

bool message_cast_bool(message m) {
    return m->query &&
           ((m->code >= 200 && m->code < 300) ||
            (m->code == 0 && (m->content || len(m->headers) > 0)));
}

string message_text(message m) {
    return cast(string, m->content);
}

map message_cookies(message m) {
    string cookies = get(m->headers, str("Set-Cookie"));
    if (!cookies)
        return new(map);

    string decoded = uri_decode(cookies);
    array parts = split(decoded, str(","));
    string all = get(parts, 0);
    array pairs = split(all, str(";"));
    map result = new(map);

    each(pairs, string, pair) {
        array kv = split(pair, str("="));
        if (len(kv) < 2)
            continue;
            
        string key = get(kv, 0);
        string val = get(kv, 1);
        set(result, key, val);
    }

    return result;
}


bool message_write_status(message m, sock sc) {
    mx status = str("Status");
    i32 code = contains(m->headers, status) ? 
               cast(i32, get(m->headers, status)) : 
               (m->code ? cast(i32, m->code) : 200);
    return send_str(sc, format("HTTP/1.1 %i %s\r\n", code, code_symbol(code)));
}


bool message_write_headers(message m, sock sc) {
    each(m->headers, pair, p) {
        string k = cast(string, p->key);
        if (strcmp(k->chars, "Status") == 0 || !p->value)
            continue;
            
        if (!send_str(sc, format("%s: %s", k->chars, p->value->chars)))
            return false;
            
        if (!send(sc, "\r\n", 2))
            return false;
    }
    return send(sc, "\r\n", 2);
}


bool message_write(message m, sock sc) {
    i32 ic = cast(i32, m->code);
    if (ic > 0) {
        symbol s = code_symbol(ic);
        verify(s, "invalid status code");
        string header = format("HTTP/1.1 %i %s\r\n", ic, s);
        if (!send_str(sc, header))
            return false;
    }

    if (m->content) {
        AType ct = isa(m->content);
        
        if (!contains(m->headers, "Content-Type") && 
            (ct == typeid(map) || ct == typeid(object)))
            set(m->headers, "Content-Type", "application/json");
            
        set(m->headers, "Connection", "keep-alive");
        
        if (contains(m->headers, "Content-Type") && 
            strcmp(get(m->headers, "Content-Type"), "application/json") == 0) {
            // TODO: JSON stringify
            return false;
        } else if (ct == typeid(map)) {
            string post = uri_encode_fields(cast(map, m->content));
            set(m->headers, "Content-Length", str(len(post)));
            write_headers(m, sc);
            return send_str(sc, post);
        } else if (ct == typeid(u8)) {
            set(m->headers, "Content-Length", str(len(m->content)));
            return send(sc, data(m->content), len(m->content));
        } else {
            verify(ct == typeid(string), "unsupported content type");
            set(m->headers, "Content-Length", str(len(m->content)));
            write_headers(m, sc);
            return send_str(sc, cast(string, m->content));
        }
    }
    
    set(m->headers, "Content-Length", "0");
    set(m->headers, "Connection", "keep-alive");
    return write_headers(m, sc);
}


string uri_addr(uri u) {
    return dns(u->host);
}

string dns(string hostname) {
    struct addrinfo hints = {0}, *res, *p;
    i32 status;
    char ip[INET6_ADDRSTRLEN];
    
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    status = getaddrinfo(hostname->chars, null, &hints, &res);
    if (status != 0) {
        print("DNS lookup failed: %i", status);
        return null;
    }

    string result = null;
    for (p = res; p != null; p = p->ai_next) {
        void* addr;
        if (p->ai_family == AF_INET) {
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
            addr = &(ipv4->sin_addr);
        } else {
            struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
            addr = &(ipv6->sin6_addr);
        }

        char* ip_str = inet_ntop(p->ai_family, addr, ip, sizeof(ip));
        if (ip_str) {
            result = str(ip_str);
            break;
        }
    }

    freeaddrinfo(res);
    return result;
}

object request(uri url, map args) {
    map st_headers = new(map);
    object null_content = null;
    map headers = contains(args, "headers") ? get(args, "headers") : st_headers;
    object content = contains(args, "content") ? get(args, "content") : null_content;
    web type = contains(args, "method") ? cast(web, get(args, "method")) : web_Get;
    uri query = url;
    query->mtype = type;

    verify(query->mtype != web_undefined, "undefined web method type");

    sock client = new(sock, query);
    print("(net) request: %o", url);
    if (!connect(client))
        return null;

    // Send request line
    string method = str(cast(string, query->mtype));
    send_str(client, format("%s %s HTTP/1.1\r\n", method->chars, query->string->chars));

    // Default headers
    if (!contains(headers, "User-Agent"))
        set(headers, "User-Agent", "ion:net");
    if (!contains(headers, "Accept"))
        set(headers, "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    if (!contains(headers, "Accept-Language"))
        set(headers, "Accept-Language", "en-US,en;q=0.9");
    if (!contains(headers, "Accept-Encoding"))
        set(headers, "Accept-Encoding", "gzip, deflate, br");
    if (!contains(headers, "Host"))
        set(headers, "Host", query->host);

    message request = new(message, content, headers, query);
    write(request, client);

    message response = new(message, client);
    close(client);

    return response;
}

object json_request(uri addr, map args, map headers) {
    // JSON request implementation goes here - would need implementation details
    // for the lambda/future mechanics in the A-type system
    verify(false, "json_request not implemented");
    return null;
}

string uri_encode(string s) {
    static string chars = str(" -._~:/?#[]@!$&'()*+;%=");
    
    sz len = len(s);
    vector v = new(vector);
    
    for (sz i = 0; i < len; i++) {
        char c = s->chars[i];
        bool a = ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'));
        if (!a)
            a = index_of(chars, str(c)) != -1;
            
        if (!a) {
            push(v, '%');
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", (u8)c);
            push(v, hex[0]);
            push(v, hex[1]);
        } else {
            push(v, c);
        }
        
        if (c == '%')
            push(v, '%');
    }
    
    return string(chars, data(v), ref_length, len(v));
}

string uri_decode(string e) {
    sz sz = len(e);
    vector v = new(vector);
    sz i = 0;

    while (i < sz) {
        char c0 = e->chars[i];
        if (c0 == '%') {
            if (i >= sz - 1)
                break;
                
            char c1 = e->chars[i + 1];
            if (c1 == '%') {
                push(v, '%');
            } else {
                if (i >= sz - 2)
                    break;
                    
                char c2 = e->chars[i + 2];
                char hex[3] = {c1, c2, 0};
                u8 val;
                sscanf(hex, "%hhx", &val);
                push(v, val);
                i += 2;
            }
        } else {
            push(v, (c0 == '+') ? ' ' : c0);
        }
        i++;
    }
    
    return string(chars, data(v), ref_length, len(v));
}

// The handler function signature would be:
object handle_client(object target, object client_sock, object context) {
    sock s = client_sock;
    // Handle the client socket
    return A_bool(true);
}

object sock_listen(uri url, subprocedure handler) {
    TLS tls = new(TLS, url);
    
    for (;;) {
        sock client = accept(tls);
        if (!client)
            break;

        // handler function will receive:
        // - target from handler->target
        // - client as the data arg 
        // - context from handler->ctx
        object result = invoke(handler, client);
        if (!cast(bool, result))
            break;
    }
    return tls;
}

// Implementation wrappers
bool sock_bind(sock s, uri addr) {
    return Session_bind(s->data, addr);
}

bool sock_connect(sock s) {
    return Session_connect(s);
}

bool sock_close(sock s) {
    return Session_close(s->data);
}

none sock_set_timeout(sock s, i64 t) {
    Session_set_timeout(s->data, t);
}

bool sock_read_sz(sock s, handle v, sz sz) {
    return Session_read_sz(s->data, v, sz);
}

sz sock_recv(sock s, handle buf, sz len) {
    return Session_recv(s->data, buf, len);
}

sz sock_send_bytes(sock s, handle buf, sz len) {
    return Session_send(s->data, buf, len);
}

/// not 
sz sock_send_str(sock s, string templ, array args) {
    return Session_send_str(s->data, templ, args); 
}

sz sock_send_object(sock s, object v) {
    return Session_send_object(s->data, v);
}

vector sock_read_until(sock s, string match, i32 max_len) {
    return Session_read_until(s->data, match, max_len);
}

sock sock_accept(TLS tls) {
    return Session_accept(tls);
}

bool sock_cast_bool(sock s) {
    return s->connected;
}

bool sock_read(sock s, handle buf, sz len) {
    sz actual = recv(s, buf, len);
    return actual == len;
}

// For JSON requests, success/failure handlers would have signatures like:
object on_success(object target, object response_data, object context) {
    // Handle successful JSON response
    return response_data;
}

object on_failure(object target, object error_data, object context) {
    // Handle failure
    return null;
}

object json_request(uri addr, map args, map headers, subprocedure success_handler, subprocedure failure_handler) {
    object response = request(addr, headers);
    
    if (!response) {
        return invoke(failure_handler, null);
    }

    if (isa(response) == typeid(map)) {
        return invoke(success_handler, response);
    } else {
        return invoke(failure_handler, response);
    }
}

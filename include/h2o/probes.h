/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Fastly, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#ifndef h2o__probes_h
#define h2o__probes_h

/* This file must only be included from the source files of the h2o / libh2o, because H2O_USE_DTRACE is a symbol available only
 * during the build phase of h2o.  That's fine, because only h2o / libh2o should have the right to define probes belonging to the
 * h2o namespace.
*/
#if H2O_USE_DTRACE

#include "picotls.h"
#include "h2o-probes.h"

#ifdef __linux__
#include <linux/bpf.h>
#include <linux/unistd.h>

struct keyType {
    u_int8_t ipa[16];
    u_int8_t ipb[16];
    long porta;
    long portb;
};

#define NR_CPU 4

static int map_fd;
static char path[] = "/sys/fs/bpf/h2o_map";

inline static void open_map() {
    union bpf_attr attr;
    int fd;

    memset(&attr, 0, sizeof(attr));
    attr.pathname = (__u64) (unsigned long)&path[0];

    fd = syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
    map_fd = fd; // __sync_lock_test_and_set
}

inline static int lookup_map(const void *key, const void *value) {
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd;
    attr.key = (__u64) (unsigned long)key;
    attr.value = (__u64) (unsigned long)value;

    return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

inline static void read_ip_port(struct sockaddr *sa, void *ip, long *port) {
    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (void *)sa;
        memcpy(ip, &sin->sin_addr, sizeof(sin->sin_addr));
        *port = sin->sin_port;
     } else if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin = (void *)sa;
        memcpy(ip, &sin->sin6_addr, sizeof(sin->sin6_addr));
        *port = sin->sin6_port;
    }
}

inline static int check_map(h2o_conn_t *conn)
{
    // we already know we trace that conn or not
    if (conn->is_traced) return conn->is_traced;

    // check if map opened
    if (map_fd <= 0) {
        open_map();
        if (map_fd <= 0) return 1; // map can't be opened, fallback accepting probe
    }

    h2o_socket_t *sock = (conn)->callbacks->get_socket(conn);
    struct sockaddr_storage loc;
    struct sockaddr_storage rem;
    struct keyType key;
    __u64 vals[NR_CPU];
    memset(&vals, 0, sizeof(vals));
    memset(&key, 0, sizeof(key));

    // get sock/peer ip/ports
    h2o_socket_getsockname(sock, (void *)&loc);
    h2o_socket_getpeername(sock, (void *)&rem);

    // read ip/ports, put parsed val into key structure
    read_ip_port((void *)&loc, &key.ipa, &key.porta);
    read_ip_port((void *)&rem, &key.ipb, &key.portb);

    // lookup map for our key
    lookup_map(&key, &vals);

    // return 1 if value present in map, -1 otherwise
    conn->is_traced = -1;
    for(int i=0; i < NR_CPU; i++) if (vals[i] > 0) conn->is_traced = 1;
    return conn->is_traced;
}

#else
inline static int check_map(h2o_socket_t *sock) {
    return 1;
}
#endif

#define H2O_PROBE_CONN(label, conn, ...)                                                                                           \
    do {                                                                                                                           \
        if (PTLS_UNLIKELY(H2O_H2O_##label##_ENABLED()) && check_map(conn) == 1) {                                                  \
            H2O_H2O_##label(conn, __VA_ARGS__);                                                                                          \
        }                                                                                                                          \
    } while (0)

#define H2O_PROBE(label, ...)                                                                                                      \
    do {                                                                                                                           \
        if (PTLS_UNLIKELY(H2O_H2O_##label##_ENABLED())) {                                                                          \
            H2O_H2O_##label(__VA_ARGS__);                                                                                          \
        }                                                                                                                          \
    } while (0)

#define H2O_PROBE_HEXDUMP(s, l)                                                                                                    \
    ({                                                                                                                             \
        size_t _l = (l);                                                                                                           \
        ptls_hexdump(alloca(_l * 2 + 1), (s), _l);                                                                                 \
    })
#else

#define H2O_PROBE_CONN(label, conn, ...)
#define H2O_PROBE(label, ...)
#define H2O_PROBE_HEXDUMP(s, l)

#endif
#endif
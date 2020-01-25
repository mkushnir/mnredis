#ifndef MNREDIS_H_DEFINED
#define MNREDIS_H_DEFINED

#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <stdlib.h>
#include <stdio.h>

#include <mncommon/array.h>
#include <mncommon/bytes.h>
#include <mncommon/bytestream.h>
#include <mncommon/stqueue.h>
#include <mncommon/util.h>

#include <mnthr.h>

#ifdef __cplusplus
extern "C" {
#endif

struct _mnredis_error {
    mnbytes_t *code;
    mnbytes_t *message;
};

#define MNREDIS_UNDEF   0x20
#define MNREDIS_SSTR    '+'
#define MNREDIS_BSTR    '$'
#define MNREDIS_ERR     '-'
#define MNREDIS_INT     ':'
#define MNREDIS_ARRAY   '*'

#define MNREDIS_TY(tag) ((tag) - 0x20)

#define MNREDIS_TSSTR   MNREDIS_TY(MNREDIS_SSTR)
#define MNREDIS_TBSTR   MNREDIS_TY(MNREDIS_BSTR)
#define MNREDIS_TERR    MNREDIS_TY(MNREDIS_ERR)
#define MNREDIS_TINT    MNREDIS_TY(MNREDIS_INT)
#define MNREDIS_TARRAY  MNREDIS_TY(MNREDIS_ARRAY)

#define MNREDIS_MSEC2SEC(ms)((int64_t)((ms) / 1000 + ((ms) % 1000 ? 1 : 0)))


typedef struct _mnredis_value {
    union {
        int64_t i;
        mnbytes_t *s;
        mnarray_t *a;
        struct _mnredis_error e;
    } v;
    int ty;
} mnredis_value_t;


typedef struct _mnredis_response {
    mnredis_value_t val;
} mnredis_response_t;


typedef struct _mnredis_request {
    STQUEUE_ENTRY(_mnredis_request, link);
    mnarray_t args;
    mnthr_signal_t recv_signal;
    mnredis_response_t *resp;
} mnredis_request_t;


typedef struct _mnredis_connection {
    mnbytes_t *host;
    mnbytes_t *port;
    int fd; /* connect socket */
    void *fp;
    mnthr_ctx_t *send_thread;
    mnthr_signal_t send_signal;
    mnthr_ctx_t *recv_thread;
    mnbytestream_t in;
    mnbytestream_t out;
    mnthr_sema_t sema;
    STQUEUE(_mnredis_request, requests_out);
    STQUEUE(_mnredis_request, requests_in);
} mnredis_connection_t;


typedef struct _mnredis_ctx {
    mnredis_connection_t conn;
} mnredis_ctx_t;


typedef struct _mnredis_stats {
    size_t rq_out_sz;
    size_t rq_in_sz;
    size_t bs_in_sz;
    size_t bs_out_sz;
} mnredis_stats_t;

void mnredis_ctx_init(mnredis_ctx_t *, mnbytes_t *, mnbytes_t *, size_t);
int mnredis_ctx_connect(mnredis_ctx_t *);

#define MNREDIS_COMMAND_ERROR   (0x8001)
#define MNREDIS_RESPONSE_ERROR  (0x8002)
int mnredis_select(mnredis_ctx_t *, int);
int mnredis_echo(mnredis_ctx_t *, mnbytes_t *, mnbytes_t **);
int mnredis_ping(mnredis_ctx_t *);
int mnredis_append(mnredis_ctx_t *, mnbytes_t *, mnbytes_t *, int64_t *);
int mnredis_decr(mnredis_ctx_t *, mnbytes_t *, int64_t *);
int mnredis_incr(mnredis_ctx_t *, mnbytes_t *, int64_t *);
int mnredis_get(mnredis_ctx_t *, mnbytes_t *, mnbytes_t **);
#define MNREDIS_NX          (0x0000000100000000ul)
#define MNREDIS_XX          (0x0000000200000000ul)
#define MNREDIS_EXPIRE_MASK (0x00000000fffffffful)
#define MNREDIS_SET_PRECOND_FAIL    (0x8002)
int mnredis_set(mnredis_ctx_t *, mnbytes_t *, mnbytes_t *, uint64_t);
int mnredis_getset(mnredis_ctx_t *, mnbytes_t *, mnbytes_t *, mnbytes_t **);
int mnredis_del(mnredis_ctx_t *, mnbytes_t *);
int mnredis_exists(mnredis_ctx_t *, mnbytes_t *, int64_t *);
int mnredis_strlen(mnredis_ctx_t *, mnbytes_t *, int64_t *);

int mnredis_hdel(mnredis_ctx_t *, mnbytes_t *, int, ...);
#define MNREDIS_HDEL(ctx, key, ...) \
    mnredis_hdel(ctx, key, MNASZ(__VA_ARGS__), ##__VA_ARGS__)
int mnredis_hexists(mnredis_ctx_t *, mnbytes_t *, mnbytes_t *, int64_t *);
int mnredis_hget(mnredis_ctx_t *, mnbytes_t *, mnbytes_t *, mnbytes_t **);
int mnredis_hincrby(mnredis_ctx_t *,
                    mnbytes_t *,
                    mnbytes_t *,
                    int64_t,
                    int64_t *);
int mnredis_hlen(mnredis_ctx_t *, mnbytes_t *, int64_t *);
int mnredis_hmget(mnredis_ctx_t *, mnarray_t **, mnbytes_t *, int, ...);
#define MNREDIS_HMGET(ctx, rv, key, ...) \
    mnredis_hmget(ctx, rv, key, MNASZ(__VA_ARGS__), ##__VA_ARGS__)
int mnredis_hmset(mnredis_ctx_t *, mnbytes_t *, int, ...);
#define MNREDIS_HMSET(ctx, key, ...) \
    mnredis_hmget(ctx, key, MNASZ(__VA_ARGS__), ##__VA_ARGS__)
int mnredis_hset(mnredis_ctx_t *,
                 mnbytes_t *,
                 mnbytes_t *,
                 mnbytes_t *,
                 int64_t *);
int mnredis_hstrlen(mnredis_ctx_t *, mnbytes_t *, mnbytes_t *, int64_t *);
int mnredis_blpop(mnredis_ctx_t *, mnbytes_t **, mnbytes_t **, int, ...);
#define MNREDIS_BLPOP(ctx, rk, rv, ...) \
    mnredis_blpop(ctx, rk, rv,  MNASZ(__VA_ARGS__), ##__VA_ARGS__)
int mnredis_brpop(mnredis_ctx_t *, mnbytes_t **, mnbytes_t **, int, ...);
#define MNREDIS_BRPOP(ctx, rk, rv, ...) \
    mnredis_brpop(ctx, rk, rv,  MNASZ(__VA_ARGS__), ##__VA_ARGS__)
int mnredis_brpoplpush(mnredis_ctx_t *,
                       mnbytes_t *,
                       mnbytes_t *,
                       int64_t,
                       mnbytes_t **);
int mnredis_rpoplpush(mnredis_ctx_t *,
                      mnbytes_t *,
                      mnbytes_t *,
                      mnbytes_t **);
int mnredis_lindex(mnredis_ctx_t *, mnbytes_t *, int64_t, mnbytes_t **);
int mnredis_linsert(mnredis_ctx_t *,
                    mnbytes_t *,
                    mnbytes_t *,
                    mnbytes_t *,
                    mnbytes_t *,
                    int64_t *);
int mnredis_linsert_before(mnredis_ctx_t *,
                           mnbytes_t *,
                           mnbytes_t *,
                           mnbytes_t *,
                           int64_t *);
int mnredis_linsert_after(mnredis_ctx_t *,
                          mnbytes_t *,
                          mnbytes_t *,
                          mnbytes_t *,
                          int64_t *);
int mnredis_llen(mnredis_ctx_t *, mnbytes_t *, int64_t *);
int mnredis_lpop(mnredis_ctx_t *, mnbytes_t *, mnbytes_t **);
int mnredis_rpop(mnredis_ctx_t *, mnbytes_t *, mnbytes_t **);
int mnredis_lpush(mnredis_ctx_t *, int64_t *, mnbytes_t *, int, ...);
#define MNREDIS_LPUSH(ctx, rv, key, ...)    \
    mnredis_lpush(ctx, rv, key, MNASZ(__VA_ARGS__), ##__VA_ARGS__)
int mnredis_lpushx(mnredis_ctx_t *, mnbytes_t *, mnbytes_t *, int64_t *);
int mnredis_rpush(mnredis_ctx_t *, int64_t *, mnbytes_t *, int, ...);
#define MNREDIS_RPUSH(ctx, rv, key, ...)    \
    mnredis_rpush(ctx, rv, key, MNASZ(__VA_ARGS__), ##__VA_ARGS__)
int mnredis_rpushx(mnredis_ctx_t *, mnbytes_t *, mnbytes_t *, int64_t *);
int mnredis_ltrim(mnredis_ctx_t *, mnbytes_t *, int64_t, int64_t);
int mnredis_lrange(mnredis_ctx_t *,
                   mnbytes_t *,
                   int64_t,
                   int64_t,
                   mnarray_t **);
int mnredis_lrem(mnredis_ctx_t *,
                 mnbytes_t *,
                 int64_t,
                 mnbytes_t *,
                 int64_t *);
int mnredis_lset(mnredis_ctx_t *,
                 mnbytes_t *,
                 int64_t,
                 mnbytes_t *);

//int mnredis_quit(mnredis_ctx_t *);

bool mnredis_need_reconnect(mnredis_ctx_t *);
int mnredis_ctx_reconnect(mnredis_ctx_t *);
void mnredis_ctx_fini(mnredis_ctx_t *);
void mnredis_ctx_stats(mnredis_ctx_t *, mnredis_stats_t *);

#ifdef __cplusplus
}
#endif
#endif /* MNREDIS_H_DEFINED */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <inttypes.h> /* strtoimax() */
#include <sys/socket.h>

//#define TRRET_DEBUG
#include <mrkcommon/dumpm.h>
#include <mrkcommon/util.h>

#include <mnredis.h>

#include "diag.h"


#define MNREDIS_NEEDMORE (-2)
static mnbytes_t _echo = BYTES_INITIALIZER("ECHO");
static mnbytes_t _ping = BYTES_INITIALIZER("PING");
static mnbytes_t _select = BYTES_INITIALIZER("SELECT");
static mnbytes_t _append = BYTES_INITIALIZER("APPEND");
static mnbytes_t _decr = BYTES_INITIALIZER("DECR");
static mnbytes_t _incr = BYTES_INITIALIZER("INCR");
static mnbytes_t _set = BYTES_INITIALIZER("SET");
static mnbytes_t _get = BYTES_INITIALIZER("GET");
static mnbytes_t _del = BYTES_INITIALIZER("DEL");
static mnbytes_t _exists = BYTES_INITIALIZER("EXISTS");
static mnbytes_t _getset = BYTES_INITIALIZER("GETSET");
static mnbytes_t _mnredis_error = BYTES_INITIALIZER("MNREDIS_ERROR");

/*
 * mnredis_value_t
 */

void
mnredis_value_dump(mnredis_value_t *val, int level)
{
    switch (val->ty) {
    case MNREDIS_TSSTR:
        LTRACE(level, "<sstr %s>", BDATASAFE(val->v.s));
        break;

    case MNREDIS_TBSTR:
        LTRACE(level, "<bstr %s>", BDATASAFE(val->v.s));
        break;

    case MNREDIS_TERR:
        LTRACE(level, "<err %s %s>", BDATASAFE(val->v.e.code), BDATASAFE(val->v.e.message));
        break;

    case MNREDIS_TINT:
        LTRACE(level, "<int %ld>", val->v.i);
        break;

    case MNREDIS_TARRAY:
        {
            mnredis_value_t *v;
            mnarray_iter_t it;

            LTRACE(level, "<array:");
            for (v = array_first(val->v.a, &it);
                 v != NULL;
                 v = array_next(val->v.a, &it)) {
                mnredis_value_dump(v, level + 1);
            }
            LTRACE(level, ">");
        }
        break;

    default:
        LTRACE(level, "<val@%p>", val);
    }
}


static void
mnredis_value_fini(mnredis_value_t *val)
{
    switch (val->ty) {
    case MNREDIS_TSSTR:
    case MNREDIS_TBSTR:
        BYTES_DECREF(&val->v.s);
        break;

    case MNREDIS_TERR:
        BYTES_DECREF(&val->v.e.code);
        BYTES_DECREF(&val->v.e.message);
        break;

    case MNREDIS_TARRAY:
        array_destroy(&val->v.a);
        break;

    default:
        ;
    }
    val->ty = MNREDIS_TY(MNREDIS_UNDEF);
}


static int
mnredis_value_item_fini(mnredis_value_t *val)
{
    switch (val->ty) {
    case MNREDIS_TARRAY:
        {
            mnredis_value_t *v;
            mnarray_iter_t it;
            for (v = array_first(val->v.a, &it);
                 v != NULL;
                 v = array_next(val->v.a, &it)) {
                mnredis_value_fini(v);
            }
            val->ty = MNREDIS_TY(MNREDIS_UNDEF);
        }
        break;

    default:
        mnredis_value_fini(val);
    }
    return 0;
}


/*
 * mnredis_response_t
 */
static mnredis_response_t *
mnredis_response_new(void)
{
    mnredis_response_t *res;

    if (MRKUNLIKELY((res = malloc(sizeof(mnredis_response_t))) == NULL)) {
        FAIL("malloc");
    }
    res->val.ty = MNREDIS_UNDEF;

    return res;
}

static void
mnredis_response_destroy(mnredis_response_t **resp)
{
    if (*resp != NULL) {
        mnredis_value_fini(&(*resp)->val);
        free(*resp);
        *resp = NULL;
    }
}


static void
mnredis_parse_error(const char *s, int len, mnredis_value_t *val)
{
    const char *p;

    assert(val->ty == MNREDIS_TERR);

    if ((p = strchr(s, ' ')) != NULL) {

        val->v.e.code = bytes_new_from_str_len(s, p - s);
        val->v.e.message = bytes_new_from_str_len(s + (p - s + 1),
                                                  len - (p - s + 1));
    } else {
        val->v.e.code = &_mnredis_error;
        val->v.e.message = bytes_new_from_str_len(s, len);
    }
    BYTES_INCREF(val->v.e.code);
    BYTES_INCREF(val->v.e.message);
}

#define MNREDIS_MAYBE_CONSUME_DATA(pred)                               \
        while (pred) {                                                 \
            if ((res = bytestream_consume_data(bs, fp)) != 0) {        \
                if (res == -1) {                                       \
                    /* EOF */                                          \
                } else {                                               \
                }                                                      \
                goto err;                                              \
            }                                                          \
        }                                                              \


#define MNREDIS_PARSE_SCALAR(__a0)                             \
    for (idx = 0; ; ++idx) {                                   \
        char ch0, ch1;                                         \
        MNREDIS_MAYBE_CONSUME_DATA((SAVAIL(bs) - idx) < 2)     \
        ch0 = SNCHR(bs, SPOS(bs) + idx);                       \
        ch1 = SNCHR(bs, SPOS(bs) + idx + 1);                   \
        if (ch0 == '\r' && ch1 == '\n') {                      \
            __a0                                               \
        }                                                      \
    }                                                          \


static int
mnredis_parse_value(mnbytestream_t *bs, void *fp, mnredis_value_t *val)
{
    int res;

    res = 0;
    while (true) {
        char tag;
        int idx;

        MNREDIS_MAYBE_CONSUME_DATA(SNEEDMORE(bs));

        tag = SPCHR(bs);
        SINCR(bs);
        val->ty = MNREDIS_TY(tag);

        if (tag == MNREDIS_SSTR) {
            MNREDIS_PARSE_SCALAR(
                val->v.s = bytes_new_from_str_len(SPDATA(bs), idx);
                BYTES_INCREF(val->v.s);
                SADVANCEPOS(bs, idx + 2);
                goto end;
            );

        } else if (tag == MNREDIS_BSTR) {
            intmax_t len;

            MNREDIS_PARSE_SCALAR(
                len = strtoimax(SPDATA(bs), NULL, 10);
                SADVANCEPOS(bs, idx + 2);
                break;
            );

            if (len < 0) {
                val->v.s = NULL;

            } else {
                /* XXX check for max len */
                if (len == 0) {
                    if (errno == EINVAL) {
                        res = MNREDIS_PARSE_VALUE + 1;
                        goto err;
                    }
                }
                MNREDIS_MAYBE_CONSUME_DATA(SAVAIL(bs) < (len + 2));
                val->v.s = bytes_new_from_str_len(SPDATA(bs), len);
                BYTES_INCREF(val->v.s);
                /*
                 * XXX check
                 *  SDATA(bs, SPOS(bs) + idx) == '\r'
                 *  SDATA(bs, SPOS(bs) + idx + 1) == '\n'
                 */
                SADVANCEPOS(bs, idx + 2);
            }

            goto end;

        } else if (tag == MNREDIS_INT) {
            MNREDIS_PARSE_SCALAR(
                val->v.i = strtoimax(SPDATA(bs), NULL, 10);
                SADVANCEPOS(bs, idx + 2);
                goto end;
            );

            if (val->v.i == 0) {
                if (errno == EINVAL) {
                    res = MNREDIS_PARSE_VALUE + 2;
                    goto err;
                }
            }

        } else if (tag == MNREDIS_ERR) {
            MNREDIS_PARSE_SCALAR(
                mnredis_parse_error(SPDATA(bs), idx, val);
                SADVANCEPOS(bs, idx + 2);
                goto end;
            );

        } else if (tag == MNREDIS_ARRAY) {
            intmax_t len;
            MNREDIS_PARSE_SCALAR(
                len = strtoimax(SPDATA(bs), NULL, 10);
                SADVANCEPOS(bs, idx + 2);
                break;
            );

            if (len < 0) {
                val->v.a = NULL;

            } else {
                mnredis_value_t *v;
                mnarray_iter_t it;

                /* XXX check for max len */
                if (len == 0) {
                    if (errno == EINVAL) {
                        res = MNREDIS_PARSE_VALUE + 3;
                        goto err;
                    }
                }

                val->v.a = array_new(
                        sizeof(mnredis_value_t),
                        len,
                        NULL,
                        (array_finalizer_t)mnredis_value_item_fini);

                for (v = array_first(val->v.a, &it);
                     v != NULL;
                     v = array_next(val->v.a, &it)) {
                    if ((res = mnredis_parse_value(bs, fp, v)) != 0) {
                        goto err;
                    }
                }
            }

        } else {
        }
    }

end:
    return res;

err:
    goto end;
}


static int
mnredis_parse_response(mnbytestream_t *bs, void *fp, mnredis_response_t **resp)
{
    int res;

    *resp = mnredis_response_new();

    if ((res = mnredis_parse_value(bs, fp, &(*resp)->val)) != 0) {
        mnredis_response_destroy(resp);
    }
    return res;
}


/*
 * mnredis_request_t
 */
static void
mnredis_request_init(mnredis_request_t *req, size_t nargs)
{
    STQUEUE_ENTRY_INIT(link, req);
    if (array_init(&req->args,
                   sizeof(mnbytes_t *),
                   nargs,
                   NULL,
                   (array_finalizer_t)bytes_decref) != 0) {
        FAIL("array_init");
    }
    MRKTHR_SIGNAL_INIT(&req->recv_signal);
    req->resp = NULL;
}


static void
mnredis_request_fini(mnredis_request_t *req)
{
    STQUEUE_ENTRY_FINI(link, req);
    mrkthr_signal_fini(&req->recv_signal);
    (void)array_fini(&req->args);
    mnredis_response_destroy(&req->resp);
}


/*
 * pack
 */
ssize_t
mnredis_pack_int(mnbytestream_t *bs, int64_t v)
{
    return bytestream_nprintf(bs, 64, ":%ld\r\n", v);
}


ssize_t
mnredis_pack_alen(mnbytestream_t *bs, int64_t v)
{
    return bytestream_nprintf(bs, 64, "*%ld\r\n", v);
}


ssize_t
mnredis_pack_bstrz(mnbytestream_t *bs, mnbytes_t *v)
{
    assert(v != NULL);
    return bytestream_nprintf(bs,
                              8 + BSZ(v),
                              "$%ld\r\n%s\r\n",
                              BSZ(v) - 1,
                              BDATA(v));
}


ssize_t
mnredis_pack_bstr(mnbytestream_t *bs, mnbytes_t *v)
{
    assert(v != NULL);
    return bytestream_nprintf(bs,
                              8 + BSZ(v),
                              "$%ld\r\n%s\r\n",
                              BSZ(v),
                              BDATA(v));
}


/*
 * commands
 */
#define MNREDIS_CMD_BODY(ecode, __a0)                                  \
    int res;                                                           \
    mnredis_request_t req;                                             \
    mnbytes_t **a;                                                     \
    mnarray_iter_t it;                                                 \
    res = 0;                                                           \
    mnredis_request_init(&req, countof(args));                         \
    for (a = array_first(&req.args, &it);                              \
         a != NULL;                                                    \
         a = array_next(&req.args, &it)) {                             \
        *a = args[it.iter];                                            \
        BYTES_INCREF(*a);                                              \
    }                                                                  \
    /*                                                                 \
     * first enqueue, then signal the write end                        \
     */                                                                \
    STQUEUE_ENQUEUE(&ctx->conn.requests_out, link, &req);              \
    mrkthr_signal_send(&ctx->conn.send_signal);                        \
    if (MRKUNLIKELY(mrkthr_signal_subscribe(&req.recv_signal) != 0)) { \
        res = ecode + 3;                                               \
        goto end;                                                      \
    }                                                                  \
    if (req.resp != NULL) {                                            \
        if (req.resp->val.ty == MNREDIS_TERR) {                        \
            res = MNREDIS_COMMAND_ERROR;                               \
        } else {                                                       \
            __a0                                                       \
        }                                                              \
    } else {                                                           \
        CTRACE("resp was NULL");                                       \
    }                                                                  \
end:                                                                   \
    mnredis_request_fini(&req);                                        \
    TRRET(res);                                                        \



int
mnredis_ping(mnredis_ctx_t *ctx)
{
    mnbytes_t *args[] = { &_ping, };
    MNREDIS_CMD_BODY(MNREDIS_PING,
    );
}


int
mnredis_echo(mnredis_ctx_t *ctx, mnbytes_t *s, mnbytes_t **rv)
{
    mnbytes_t *args[] = { &_echo, s, };
    MNREDIS_CMD_BODY(MNREDIS_ECHO,
        *rv = req.resp->val.v.s;
        if (*rv != NULL) {
            BYTES_INCREF(*rv);
        }
    );
}


int
mnredis_select(mnredis_ctx_t *ctx, int n)
{
    mnbytes_t *s = bytes_printf("%d", n);
    BYTES_INCREF(s);
    mnbytes_t *args[] = { &_select, s, };
    MNREDIS_CMD_BODY(MNREDIS_SELECT,
        BYTES_DECREF(&s);
    );
}


int
mnredis_append(mnredis_ctx_t *ctx, mnbytes_t *key, mnbytes_t *value)
{
    mnbytes_t *args[] = { &_append, key, value, };
    MNREDIS_CMD_BODY(MNREDIS_APPEND,
    );
}


int
mnredis_decr(mnredis_ctx_t *ctx, mnbytes_t *key)
{
    mnbytes_t *args[] = { &_decr, key, };
    MNREDIS_CMD_BODY(MNREDIS_DECR,
    );
}


int
mnredis_incr(mnredis_ctx_t *ctx, mnbytes_t *key)
{
    mnbytes_t *args[] = { &_incr, key, };
    MNREDIS_CMD_BODY(MNREDIS_INCR,
    );
}


int
mnredis_set(mnredis_ctx_t *ctx, mnbytes_t *key, mnbytes_t *value)
{
    mnbytes_t *args[] = { &_set, key, value, };
    MNREDIS_CMD_BODY(MNREDIS_SET,
    );
}


int
mnredis_get(mnredis_ctx_t *ctx, mnbytes_t *key, mnbytes_t **rv)
{
    mnbytes_t *args[] = { &_get, key, };
    MNREDIS_CMD_BODY(MNREDIS_GET,
        if (req.resp->val.ty != MNREDIS_TBSTR) {
            res = MNREDIS_GET + 10;
            goto end;
        } else {
            *rv = req.resp->val.v.s;
            if (*rv != NULL) {
                BYTES_INCREF(*rv);
            }
        }
    );
}


int
mnredis_getset(mnredis_ctx_t *ctx, mnbytes_t *key, mnbytes_t *value, mnbytes_t **rv)
{
    mnbytes_t *args[] = { &_getset, key, value, };
    MNREDIS_CMD_BODY(MNREDIS_GETSET,
        *rv = req.resp->val.v.s;
        if (*rv != NULL) {
            BYTES_INCREF(*rv);
        }
    );
}


int
mnredis_del(mnredis_ctx_t *ctx, mnbytes_t *key)
{
    mnbytes_t *args[] = { &_del, key, };
    MNREDIS_CMD_BODY(MNREDIS_DEL,
    );
}


int
mnredis_exists(mnredis_ctx_t *ctx, mnbytes_t *key, int64_t *rv)
{
    mnbytes_t *args[] = { &_exists, key, };
    MNREDIS_CMD_BODY(MNREDIS_EXISTS,
        *rv = req.resp->val.v.i;
    );
}





/*
 * mnredis_ctx_t
 */
static int
mnredis_send_thread_worker(UNUSED int argc, UNUSED void **argv)
{
    int res;
    mnredis_ctx_t *ctx;

    assert(argc == 1);
    ctx = argv[0];

    while (true) {
        //D16(SDATA(&ctx->conn.out, 0), SEOD(&ctx->conn.out));

        mnredis_request_t *req;

        while ((req = STQUEUE_HEAD(&ctx->conn.requests_out)) != NULL) {
            mnbytes_t **a;
            mnarray_iter_t it;

            STQUEUE_DEQUEUE(&ctx->conn.requests_out, link);
            STQUEUE_ENTRY_FINI(link, req);
            STQUEUE_ENQUEUE(&ctx->conn.requests, link, req);

            if (MRKUNLIKELY(
                    mnredis_pack_alen(&ctx->conn.out,
                                      (int64_t)req->args.elnum) <= 0)) {
                /*
                 * XXX
                 */
            }
            for (a = array_first(&req->args, &it);
                 a != NULL;
                 a = array_next(&req->args, &it)) {
                if (MRKUNLIKELY(mnredis_pack_bstrz(&ctx->conn.out,
                                                   *a) <= 0)) {
                    /*
                     * XXX
                     */
                }
            }
        }

        if (SAVAIL(&ctx->conn.out) > 0) {
            if (bytestream_produce_data(&ctx->conn.out, ctx->conn.fp) != 0) {
                break;
            }
            bytestream_rewind(&ctx->conn.out);
        }

        if ((res = mrkthr_signal_subscribe(&ctx->conn.send_signal)) != 0) {
            break;
        }
    }

    mrkthr_signal_fini(&ctx->conn.send_signal);
    mrkthr_decabac(ctx->conn.send_thread);
    ctx->conn.send_thread = NULL;
    //CTRACE("Exiting send thread");
    return 0;
}


static int
mnredis_recv_thread_worker(UNUSED int argc, UNUSED void **argv)
{
    mnredis_ctx_t *ctx;

    assert(argc == 1);
    ctx = argv[0];

    while (true) {
        mnredis_response_t *resp;
        mnredis_request_t *req;
        off_t recycled;

        resp = NULL;
        if (mnredis_parse_response(&ctx->conn.in, ctx->conn.fp, &resp) != 0) {
            break;
            /**/
        }
        recycled = bytestream_recycle(&ctx->conn.in, 1, SPOS(&ctx->conn.in));
        if (MRKUNLIKELY((req = STQUEUE_HEAD(&ctx->conn.requests)) == NULL)) {
            /*
             * response without request?
             */
            CTRACE("response without request?");
            mnredis_response_destroy(&resp);
        } else {
            STQUEUE_DEQUEUE(&ctx->conn.requests, link);
            /*
             * leave it to mnredis_request_fini()?
             */
            //STQUEUE_ENTRY_FINI(link, req);
            req->resp = resp;
            mrkthr_signal_send(&req->recv_signal);
        }
    }

    mrkthr_decabac(ctx->conn.recv_thread);
    ctx->conn.recv_thread = NULL;
    //CTRACE("Exiting recv thread");
    return 0;
}


int
mnredis_ctx_connect(mnredis_ctx_t *ctx)
{
    int res;

    res = 0;

    if ((ctx->conn.fd = mrkthr_socket_connect((char *)BDATA(ctx->conn.host),
                                              (char *)BDATA(ctx->conn.port),
                                              PF_UNSPEC)) == -1) {
        res = MNREDIS_CTX_CONNECT + 1;
        goto end;
    }
    ctx->conn.fp = (void *)(intptr_t)ctx->conn.fd;
    ctx->conn.recv_thread = MRKTHR_SPAWN("mnrdrcv",
                                         mnredis_recv_thread_worker,
                                         ctx);
    mrkthr_incabac(ctx->conn.recv_thread);
    ctx->conn.send_thread = MRKTHR_SPAWN("mnrdsnd",
                                         mnredis_send_thread_worker,
                                         ctx);
    mrkthr_incabac(ctx->conn.send_thread);

end:
    return res;
}

void
mnredis_ctx_fini(mnredis_ctx_t *ctx)
{
    mnredis_request_t *req;

    /*
     * By this point, no pending requests should wait.  Signal error if
     * find any.
     */
    while ((req = STQUEUE_HEAD(&ctx->conn.requests_out)) != NULL) {
        STQUEUE_DEQUEUE(&ctx->conn.requests_out, link);
        mrkthr_signal_error_and_join(&req->recv_signal, MNREDIS_CTX_FINI + 1);
    }

    while ((req = STQUEUE_HEAD(&ctx->conn.requests)) != NULL) {
        STQUEUE_DEQUEUE(&ctx->conn.requests, link);
        mrkthr_signal_error_and_join(&req->recv_signal, MNREDIS_CTX_FINI + 1);
    }

    if (ctx->conn.fd != -1) {
        close(ctx->conn.fd);
        ctx->conn.fd = -1;
        ctx->conn.fp = NULL;
        if (ctx->conn.recv_thread != NULL) {
            mrkthr_set_interrupt_and_join(ctx->conn.recv_thread);
            assert(ctx->conn.recv_thread == NULL);
        }
        if (ctx->conn.send_thread != NULL) {
            mrkthr_set_interrupt_and_join(ctx->conn.send_thread);
            assert(ctx->conn.send_thread == NULL);
        }
    }
    mrkthr_sema_fini(&ctx->conn.sema);
    BYTES_DECREF(&ctx->conn.host);
    BYTES_DECREF(&ctx->conn.port);
    bytestream_fini(&ctx->conn.in);
    bytestream_fini(&ctx->conn.out);
}


void
mnredis_ctx_init(mnredis_ctx_t *ctx,
                 mnbytes_t *host,
                 mnbytes_t *port,
                 size_t growsz)
{
    ctx->conn.host = host;
    BYTES_INCREF(ctx->conn.host);
    ctx->conn.port = port;
    BYTES_INCREF(ctx->conn.port);
    ctx->conn.fd = -1;
    ctx->conn.fp = NULL;
    ctx->conn.send_thread = NULL;
    MRKTHR_SIGNAL_INIT(&ctx->conn.send_signal);
    mrkthr_sema_init(&ctx->conn.sema, 1);
    ctx->conn.recv_thread = NULL;
    if (MRKUNLIKELY(bytestream_init(&ctx->conn.in, growsz) != 0)) {
        FAIL("bytestream_init");
    }
    ctx->conn.in.read_more = mrkthr_bytestream_read_more;
    if (MRKUNLIKELY(bytestream_init(&ctx->conn.out, growsz) != 0)) {
        FAIL("bytestream_init");
    }
    ctx->conn.out.write = mrkthr_bytestream_write;
    STQUEUE_INIT(&ctx->conn.requests_out);
    STQUEUE_INIT(&ctx->conn.requests);
}

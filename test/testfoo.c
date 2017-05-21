#include <assert.h>
#include <string.h>
#include <limits.h>
#include <inttypes.h> /* strtoimax() */
#include <signal.h>

#include <mrkcommon/bytes.h>
#include <mrkcommon/dumpm.h>
#include <mrkcommon/util.h>

#include <mrkthr.h>

#include <mnredis.h>

#include "diag.h"

#include "unittest.h"

#ifndef NDEBUG
const char *_malloc_options = "AJ";
#endif

static mnbytes_t _localhost = BYTES_INITIALIZER("localhost");
static mnbytes_t _6379 = BYTES_INITIALIZER("6379");


#ifndef SIGINFO
UNUSED
#endif
static void
myinfo(UNUSED int sig)
{
    mrkthr_dump_all_ctxes();
}


static void
test0(void)
{
    mnredis_ctx_t ctx;
    UNUSED mnbytes_t *rv;
    BYTES_ALLOCA(qwe, "qwe");
    BYTES_ALLOCA(asd, "asd");
    BYTES_ALLOCA(zxc, "zxc");
    BYTES_ALLOCA(wer, "wer");
    struct {
        long rnd;
        mnbytes_t *s;
    } data[] = {
        { 0, qwe, },
        { 0, asd, },
        { 0, zxc, },
        { 0, wer, },
    };
    UNITTEST_PROLOG_RAND;

    mnredis_ctx_init(&ctx, &_localhost, &_6379, 1024);
    if (mnredis_ctx_connect(&ctx) != 0) {
        FAIL("mnredis_connect");
    }
    if (mnredis_select(&ctx, 0) != 0) {
        FAIL("mnredis_select");
    }
    FOREACHDATA {
        mnbytes_t *rv;
        //TRACE("in=%d expected=%d", CDATA.in, CDATA.expected);
        //assert(CDATA.in == CDATA.expected);
        rv = NULL;
        if (mnredis_echo(&ctx, CDATA.s, &rv) != 0) {
            FAIL("mnredis_echo");
        }
        assert(bytes_cmp(rv, CDATA.s) == 0);
        BYTES_DECREF(&rv);
    }
    if (mnredis_ping(&ctx) != 0) {
        FAIL("mnredis_ping");
    }
    mnredis_ctx_fini(&ctx);
}

static void
test1(void)
{
    mnredis_ctx_t ctx;
    BYTES_ALLOCA(qwe, "qwe");
    BYTES_ALLOCA(asd, "asd");
    BYTES_ALLOCA(qwe0, "QWE0");
    BYTES_ALLOCA(qwe1, "QWE1");
    BYTES_ALLOCA(qwe2, "QWE2");
    struct {
        long rnd;
        mnbytes_t *key;
        mnbytes_t *value;
        int expected;
    } data[] = {
        {0, qwe, qwe0, 0 },
        {0, qwe, qwe1, 0 },
        {0, qwe, qwe2, 0 },
        {0, asd, qwe0, 0 },
        {0, asd, qwe1, 0 },
        {0, asd, qwe2, 0 },
    };
    UNITTEST_PROLOG_RAND;

    mnredis_ctx_init(&ctx, &_localhost, &_6379, 1024);
    if (mnredis_ctx_connect(&ctx) != 0) {
        FAIL("mnredis_connect");
    }
    FOREACHDATA {
        int res;
        res = mnredis_append(&ctx, CDATA.key, CDATA.value);
        TRACE("key=%s value=%s", BDATASAFE(CDATA.key), BDATASAFE(CDATA.value));
        assert(res == CDATA.expected);
    }
    mnredis_ctx_fini(&ctx);
}


static void
test2(void)
{
    mnredis_ctx_t ctx;
    BYTES_ALLOCA(qwe, "qwe");
    BYTES_ALLOCA(asd, "asd");
    BYTES_ALLOCA(qwe0, "QWE0");
    BYTES_ALLOCA(qwe1, "1");
    BYTES_ALLOCA(qwe2, "2");
    struct {
        long rnd;
        mnbytes_t *key;
        mnbytes_t *value;
        int expected;
    } data[] = {
        {0, qwe, qwe0, MNREDIS_COMMAND_ERROR },
        {0, qwe, qwe1, 0 },
        {0, qwe, qwe2, 0 },
        {0, qwe, qwe1, 0 },
        {0, asd, NULL, 0 },
    };
    UNITTEST_PROLOG_RAND;

    mnredis_ctx_init(&ctx, &_localhost, &_6379, 1024);
    if (mnredis_ctx_connect(&ctx) != 0) {
        FAIL("mnredis_connect");
    }
    FOREACHDATA {
        int res;
        mnbytes_t *rv;

        if (CDATA.value != NULL) {
            res = mnredis_set(&ctx, CDATA.key, CDATA.value);
            assert(res == 0);
        } else {
            res = mnredis_del(&ctx, CDATA.key);
            assert(res == 0);
        }
        res = mnredis_incr(&ctx, CDATA.key);
        assert(res == CDATA.expected);
        res = mnredis_decr(&ctx, CDATA.key);
        assert(res == CDATA.expected);
        rv = NULL;
        res = mnredis_get(&ctx, CDATA.key, &rv);
        CTRACE("rv=%s", BDATASAFE(rv));
        BYTES_DECREF(&rv);
    }
    mnredis_ctx_fini(&ctx);
}


static void
test3(void)
{
    mnredis_ctx_t ctx;
    BYTES_ALLOCA(qwe, "qwe");
    BYTES_ALLOCA(asd, "asd");
    struct {
        long rnd;
        mnbytes_t *key;
        mnbytes_t *value;
        int expected;
    } data[] = {
        {0, qwe, qwe, 1},
        {0, asd, NULL, 0},
    };
    UNITTEST_PROLOG_RAND;
    mnredis_ctx_init(&ctx, &_localhost, &_6379, 1024);
    if (mnredis_ctx_connect(&ctx) != 0) {
        FAIL("mnredis_connect");
    }
    FOREACHDATA {
        int res;
        int64_t rv;

        if (CDATA.value == NULL) {
            res = mnredis_del(&ctx, CDATA.key);
        } else {
            res = mnredis_set(&ctx, CDATA.key, CDATA.value);
        }
        assert(res == 0);
        res = mnredis_exists(&ctx, CDATA.key, &rv);
        assert(rv == CDATA.expected);
    }
    mnredis_ctx_fini(&ctx);
}


static void
test4(void)
{
    int res;
    mnredis_ctx_t ctx;
    BYTES_ALLOCA(qwe, "qwe");
    BYTES_ALLOCA(one, "one");
    BYTES_ALLOCA(two, "two");
    BYTES_ALLOCA(three, "three");
    struct {
        long rnd;
        mnbytes_t *value;
        mnbytes_t *expected;
    } data[] = {
        {0, one, NULL},
        {0, two, one},
        {0, three, two},
    };
    UNITTEST_PROLOG;
    mnredis_ctx_init(&ctx, &_localhost, &_6379, 1024);
    if (mnredis_ctx_connect(&ctx) != 0) {
        FAIL("mnredis_connect");
    }
    res = mnredis_del(&ctx, qwe);
    assert(res == 0);
    FOREACHDATA {
        mnbytes_t *rv;

        rv = NULL;
        res = mnredis_getset(&ctx, qwe, CDATA.value, &rv);
        assert(bytes_cmp_safe(rv, CDATA.expected) == 0);
        BYTES_DECREF(&rv);
    }
    mnredis_ctx_fini(&ctx);
}

static int _test5_i = 0;

static int
_test5(UNUSED int argc, UNUSED void **argv)
{
    UNUSED int res;
    UNUSED int i, m;
    mnredis_ctx_t *ctx;
    mnbytes_t *key;

    ctx = argv[0];
    key = argv[1];
    m = (int)(intptr_t)argv[2];

    for (i = 0; i < m; ++i) {
        res = mnredis_incr(ctx, key);
        assert(res == 0);
        ++_test5_i;
        //if (mrkthr_yield() != 0) {
        //    break;
        //}
    }
    return 0;
}


static void
test5(void)
{
    int res;
    intmax_t n;
    mnredis_ctx_t ctx;
    BYTES_ALLOCA(qwe, "qwe");
    struct {
        long rnd;
        mnbytes_t *value;
        mnbytes_t *expected;
    } data[] = {
    };
    UNITTEST_PROLOG;
    mnredis_ctx_init(&ctx, &_localhost, &_6379, 4096);
    if (mnredis_ctx_connect(&ctx) != 0) {
        FAIL("mnredis_connect");
    }
    res = mnredis_del(&ctx, qwe);
    assert(res == 0);
#define TEST5_N 100
#define TEST5_M 100
    for (i = 0; i < TEST5_N; ++i) {
        MRKTHR_SPAWN(NULL, _test5, &ctx, qwe, (void *)(intptr_t)TEST5_M);
    }
    for (n = 0; n != (TEST5_N * TEST5_M);) {
        mnbytes_t *rv;

        rv = NULL;
        CTRACE("get:");
        res = mnredis_get(&ctx, qwe, &rv);
        CTRACE("res=%s", mnredis_diag_str(res));
        //assert(res == 0);
        if (rv != NULL) {
            n = strtoimax((char *)BDATA(rv), NULL, 10);
            TRACE("n=%ld", n);
        } else {
            TRACE("rv was NULL");
        }
        BYTES_DECREF(&rv);
        if (mrkthr_sleep(1000) != 0) {
            break;
        }
    }
    mnredis_ctx_fini(&ctx);
}


static int
run0(UNUSED int argc, UNUSED void **argv)
{
    test0();
    test1();
    test2();
    test3();
    test4();
    test5();
    return 0;
}


int
main(void)
{
#ifdef SIGINFO
    if (signal(SIGINFO, myinfo) == SIG_ERR) {
        return 1;
    }
#endif
    (void)mrkthr_init();
    (void)MRKTHR_SPAWN("run0", run0);
    (void)mrkthr_loop();
    (void)mrkthr_fini();
    return 0;
}

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <inttypes.h> /* strtoimax() PRI */
#include <signal.h>

#define TRRET_DEBUG

#include <mncommon/bytes.h>
#include <mncommon/dumpm.h>
#include <mncommon/util.h>

#include <mnthr.h>

#include <mnredis.h>

#include "diag.h"

#include "unittest.h"

#ifndef NDEBUG
const char *_malloc_options = "AJ";
#endif

UNUSED static mnbytes_t _localhost = BYTES_INITIALIZER("127.0.0.1");
UNUSED static mnbytes_t _vmpear_103 = BYTES_INITIALIZER("10.1.3.103");
#define TEST_REDIS _vmpear_103
static mnbytes_t _6379 = BYTES_INITIALIZER("6379");

#define NNN 10000
#define MMM 3000

static mnredis_ctx_t ctx;


static int
myshutdown(UNUSED int argc, UNUSED void **argv)
{
    mnredis_ctx_fini(&ctx);
    (void)mnthr_shutdown();
    return 0;
}


static void
myterm(UNUSED int sig)
{
    MNTHR_SPAWN_SIG("shutdwn", myshutdown);
}


#ifndef SIGINFO
UNUSED
#endif
static void
myinfo(UNUSED int sig)
{
    mnthr_dump_all_ctxes();
}


static int _numrequests;

static int
mymonitor(UNUSED int argc, UNUSED void **argv)
{
    int res;
    mnredis_stats_t stats;

    while (true) {
        if ((res = mnthr_sleep(5000)) != 0) {
            char buf[64];

            mndiag_local_str(res, buf, sizeof(buf));
            CTRACE("mnthr_sleep() returned %s",
                   MNTHR_IS_CO_RC(res) ? MNTHR_CO_RC_STR(res) : buf);
            if (res == (int)MNTHR_CO_RC_POLLER) {
                mnthr_set_retval(0);
                continue;
            }
            break;
        }
        mnredis_ctx_stats(&ctx, &stats);
        CTRACE("out=%zd/%zd in=%zd/%zd nreq=%d",
               stats.rq_out_sz,
               stats.bs_out_sz,
               stats.rq_in_sz,
               stats.bs_in_sz,
               _numrequests);
        _numrequests = 0;
        if (mnredis_need_reconnect(&ctx)) {
            CTRACE("Reconnecting ...");
            if ((res = mnredis_ctx_reconnect(&ctx)) != 0) {
                char buf[64];

                mndiag_local_str(res, buf, sizeof(buf));
                CTRACE("reconnect failed: %s", buf);
                continue;
            }
            CTRACE("...OK");
        }
    }
    CTRACE("Exiting monitor");
    return 0;
}


UNUSED static int
worker0(UNUSED int argc, UNUSED void **argv)
{
    int i;

    i = (int)(intptr_t)argv[0];

    while (true) {
        int res;
        int64_t tmout;
        mnbytes_t *key, *value;

        tmout = random() % MMM;

        key = bytes_printf("key-%d-%"PRId64, i, tmout);
        BYTES_INCREF(key);
        value = bytes_new(tmout + 1);
        BYTES_INCREF(value);
        bytes_memsetz(value, 'Z');

        //CTRACE("new %s", BDATA(key));
        res = mnredis_set(&ctx, key, value, tmout * 17);
        BYTES_DECREF(&key);
        BYTES_DECREF(&value);
        ++_numrequests;
        //TRACEC(".");

        if (res != 0) {
            char buf[64];

            mndiag_local_str(res, buf, sizeof(buf));
            CTRACE("error was %s", buf);
        }

        if ((res = mnthr_sleep(tmout)) != 0) {
            char buf[64];

            mndiag_local_str(res, buf, sizeof(buf));
            CTRACE("mnthr_sleep() returned %s", buf);
            break;
        }
        //CTRACE("tmout was %"PRId64, tmout);
    }

    CTRACE("Exiting worker ...");
    return 0;
}


UNUSED static int
worker1(UNUSED int argc, UNUSED void **argv)
{
    int i, j;

    i = (int)(intptr_t)argv[0];
    j = 0;
    while (true) {
        int res;
        mnbytes_t *key, *value;

        ++j;

        key = bytes_printf("key-%d-%d", i, j);
        BYTES_INCREF(key);
        value = bytes_new(j + 1);
        BYTES_INCREF(value);
        bytes_memsetz(value, 'Z');
        CTRACE("j=%d key=%s value(%zd)=%s", j, BDATA(key), BSZ(value), BDATA(value));

        res = mnredis_set(&ctx, key, value, j * 17);
        BYTES_DECREF(&key);
        BYTES_DECREF(&value);

        if (res != 0) {
            char buf[64];

            mndiag_local_str(res, buf, sizeof(buf));
            CTRACE("res=%s", buf);
            switch (res) {
            case MNREDIS_COMMAND_ERROR:
                break;

            default:
                goto end;
            }
        }

        if (mnthr_sleep(100) != 0) {
            break;
        }

    }

end:
    return 0;
}


static int
run0(UNUSED int argc, UNUSED void **argv)
{
    int i, res;

    mnredis_ctx_init(&ctx, &TEST_REDIS, &_6379, 4096);

    while ((res = mnredis_ctx_connect(&ctx)) != 0) {
        CTRACE("res=%d reconnecting ...", res);
        if (mnthr_sleep(1000) != 0) {
            goto end;
        }
    }

    MNTHR_SPAWN("mymon", mymonitor);


    for (i = 0; i < NNN; ++i) {
        char buf[8];
        (void)snprintf(buf, sizeof(buf), "w%d", i);
        MNTHR_SPAWN(buf, worker0, (void *)(intptr_t)i);
    }

end:
    return 0;
}


int
main(void)
{
    if (signal(SIGINT, myterm) == SIG_ERR) {
        return 1;
    }
    if (signal(SIGTERM, myterm) == SIG_ERR) {
        return 1;
    }
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        return 1;
    }
#ifdef SIGINFO
    if (signal(SIGINFO, myinfo) == SIG_ERR) {
        return 1;
    }
#endif

    (void)mnthr_init();
    (void)MNTHR_SPAWN("run0", run0);
    (void)mnthr_loop();
    (void)mnthr_fini();
    return 0;
}


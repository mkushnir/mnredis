#include <assert.h>
#include <err.h>
#include <getopt.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_MALLOC_H
#   include <malloc.h>
#endif

#include <mrkcommon/dumpm.h>
#include <mrkcommon/util.h>

#include "diag.h"

#ifndef NDEBUG
const char *_malloc_options = "AJ";
#endif

#define FOO_OPT_DEFAULT_CONFIG_FILE "/usr/local/etc/foo.conf"
static char *configfile = NULL;

static struct option longopts[] = {
#define GENDATA_OPT_FILE 0
    {"file", required_argument, NULL, 'f'},
#define GENDATA_OPT_HELP 1
    {"help", no_argument, NULL, 'h'},
#define GENDATA_OPT_DRYRUN 2
    {"dryrun", optional_argument, NULL, 'n'},
    {NULL, 0, NULL, 0},
};


static void
usage(char *progname)
{
    printf("Usage: %s [OPTIONS]\n"
        "\n"
        "Options:\n"
        "  -f PATH, --file=PATH     File to use.\n"
        "  -n, --dryrun[=ARG]       Dry run.\n"
        "  -h, --help               Print help message and exit.\n"
        "\n",
        basename(progname));
}


#ifndef SIGINFO
UNUSED
#endif
static void
myinfo(UNUSED int sig)
{
    //mrkthr_dump_all_ctxes();
}


static void
myterm(UNUSED int sig)
{
    //qwe_shutdown(0);
}


int
main(UNUSED int argc, char **argv)
{
    char ch;

#ifdef HAVE_MALLOC_H
#   ifndef NDEBUG
    /*
     * malloc options
     */
    if (mallopt(M_CHECK_ACTION, 1) != 1) {
        FAIL("mallopt");
    }
    if (mallopt(M_PERTURB, 0x5a) != 1) {
        FAIL("mallopt");
    }
#   endif
#endif

    /*
     * install signal handlers
     */
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


    while ((ch = getopt_long(argc, argv, "f:hn", longopts, NULL)) != -1) {
        switch (ch) {
        case 'f':
            TRACE("file: %s", optarg);
            break;

        case 'h':
            usage(argv[0]);
            exit(0);
            break;

        case 'n':
            TRACE("Dry run");
            break;

        case ':':
            /* missing option argument */
            usage(argv[0]);
            errx(1, "Missing option argument");
            break;

        case '?':
            /* unknown option */
            usage(argv[0]);
            errx(1, "Unknown option");
            break;

        default:
            usage(argv[0]);
            errx(1, "Unknown error");
            break;

        }
    }

    argc -= optind;
    argv += optind;

    if (configfile != NULL) {
        free(configfile);
        configfile = NULL;
    }
    return 0;
}

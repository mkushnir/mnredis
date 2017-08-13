# consider headers:
#   - include_HEADERS
#   - nobase_include_HEADERS
#   - pkginclude_HEADERS
#   - dist_HEADERS
#   - nodist_HEADERS
#   - noinst_HEADERS

BUILT_SOURCES = diag.c diag.h
EXTRA_DIST = $(diags)
CLEANFILES = $(BUILT_SOURCES) *.core core
#CLEANFILES += *.in
AM_MAKEFLAGS = -s

lib_LTLIBRARIES = libmnredis.la

nobase_include_HEADERS = mnredis.h

libmnredis_la_SOURCES = mnredis.c
nodist_libmnredis_la_SOURCES = diag.c

diags = diag.txt

if DEBUG
DEBUG_FLAGS = -g -O0 @CC_DEBUG@
else
DEBUG_FLAGS = -DNDEBUG -O3 -fomit-frame-pointer
endif

libmnredis_la_CFLAGS = $(DEBUG_FLAGS) -Wall -Wextra -Werror -std=c99 @_GNU_SOURCE_MACRO@ -I$(top_srcdir)/src -I$(top_srcdir) -I$(includedir)

#libmnredis_la_LDFLAGS = -version-info 0:0:0
libmnredis_la_LDFLAGS = -version-info 0:0:0 -L$(libdir) -lmrkapp -lmrkthr -lmrkcommon -lmndiag
#libmnredis_la_LDFLAGS = -all-static
#libmnredis_la_LDFLAGS = -all-static -Wl,-Bdynamic,-L$(libdir),-lfoo -lqwe,-Bstatic

diag.c diag.h: $(diags)
	$(AM_V_GEN) cat $(diags) | sort -u >diag.txt.tmp && mndiagen -v -S diag.txt.tmp -L mnredis -H diag.h -C diag.c *.[ch]

run: all
	for i in $(bin_PROGRAMS); do if test -x ./$$i; then LD_LIBRARY_PATH=$(libdir) ./$$i; fi; done;

testrun:
	for i in $(SUBDIRS); do if test "$$i" != "."; then cd $$i && $(MAKE) testrun && cd ..; fi; done;

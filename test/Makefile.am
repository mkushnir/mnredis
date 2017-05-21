CLEANFILES = *.core core
#CLEANFILES += *.in
AM_MAKEFLAGS = -s

# consider headers:
#   - include_HEADERS
#   - nobase_include_HEADERS
#   - pkginclude_HEADERS
#   - dist_HEADERS
#   - nodist_HEADERS
#   - noinst_HEADERS
noinst_HEADERS = unittest.h

noinst_PROGRAMS=testfoo gendata

BUILT_SOURCES = diag.c diag.h gen-diag
EXTRA_DIST = $(diags) gen-diag runscripts

#noinst_HEADERS = ../src/mnredis.h

diags = diag.txt ../src/diag.txt

if DEBUG
DEBUG_FLAGS = -g -O0 @CC_DEBUG@
else
DEBUG_FLAGS = -DNDEBUG -O3 -fomit-frame-pointer
endif

nodist_testfoo_SOURCES = diag.c
testfoo_SOURCES = testfoo.c
testfoo_CFLAGS = $(DEBUG_FLAGS) -Wall -Wextra -Werror -std=c99 @_GNU_SOURCE_MACRO@ -I$(top_srcdir)/test -I$(top_srcdir)/src -I$(top_srcdir) -I$(includedir)
#testfoo_LDFLAGS = -L$(libdir) -lmrkcommon -L$(top_srcdir)/src/.libs -lmnredis
testfoo_LDFLAGS = -L$(top_srcdir)/src/.libs -lmnredis -L$(libdir) -lmrkapp -lmrkthr -lmrkcommon

nodist_gendata_SOURCES = diag.c
gendata_SOURCES = gendata.c
gendata_CFLAGS = $(DEBUG_FLAGS) -Wall -Wextra -Werror -std=c99 @_GNU_SOURCE_MACRO@ -I$(top_srcdir)/test -I$(top_srcdir)/src -I$(top_srcdir) -I$(includedir)
gendata_LDFLAGS = -L$(libdir) -lmrkcommon 
#gendata_LDFLAGS = 

diag.c diag.h: $(diags) gen-diag
	$(AM_V_GEN) cat $(diags) | sort -u | ./gen-diag mnredis ../src

testfoo-run: testfoo
	@if test -x $>; \
	    then LD_LIBRARY_PATH=$(libdir) ./$> $${$(>)_ARGS}; \
	    else true; \
	fi

testrun: all
	for i in $(noinst_PROGRAMS); do if test -x ./$$i; then LD_LIBRARY_PATH=$(libdir) ./$$i; fi; done;

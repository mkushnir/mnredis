AC_INIT(mnredis, 0.1, markiyan.kushnir@gmail.com, mnredis, https://github.com/mkushnir)

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([.ac-aux])
AC_CONFIG_FILES([Makefile src/Makefile test/Makefile man/Makefile])
AC_CONFIG_HEADERS(config.h)

if test -n "$USE_GCC"
then
    probe="gcc${USE_GCC}"
    if which $probe >/dev/null
    then
        CC="gcc${USE_GCC}"
        CXX="c++${USE_GCC}"
        CPP="cpp"
    else
        if which gcc >/dev/null
        then
            CC="gcc"
            CXX="g++"
            CPP="cpp"
        else
            echo "Cannot find gcc"
            exit 1
        fi
    fi
else
    if which clang >/dev/null
    then
        CC="clang -Qunused-arguments -fcolor-diagnostics"
        CXX="clang++ -Qunused-arguments -fcolor-diagnostics"
        CPP="clang-cpp"
        #clang_version=`clang --version | grep version | awk '{print $4;}'`
        #clang_version_mjr=`echo $clang_version | awk -F. '{print $1;}'`
        #clang_version_mnr=`echo $clang_version | awk -F. '{print $2;}'`
    else
        CC="cc"
        CXX="c++"
        CPP="cpp"
    fi
fi

AC_SUBST(CC_DEBUG, ['-ftrapv'])

AC_CANONICAL_HOST
AC_CANONICAL_TARGET
case "$target_os" in
    *linux*)
        AC_SUBST(_GNU_SOURCE_MACRO, ['-D_GNU_SOURCE'])
    ;;
    *)
        AC_SUBST(_GNU_SOURCE_MACRO)
    ;;
esac


AC_LANG(C)

AC_PROG_CC
AC_PROG_CXX
AM_PROG_AR
AC_PROG_INSTALL

LT_INIT
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])

dnl AM_MAINTAINER_MODE

AC_FUNC_MALLOC
AC_FUNC_REALLOC

AC_PRESERVE_HELP_ORDER

AC_ARG_ENABLE(debug,
              AC_HELP_STRING([--enable-debug],
                             [Enable debug build (default=no)]),
              [AM_CONDITIONAL([DEBUG], [enable_debug=yes])],
              [AM_CONDITIONAL([DEBUG], [test "$enable_debug" = "yes"])])

AM_CONDITIONAL([LINUX], [echo $build_os | grep linux >/dev/null])
AM_CONDITIONAL([FREEBSD], [echo $build_os | grep freebsd >/dev/null])

#dnl pass LDFLAGS=-L${LOCALBASE}/lib in the environment
#AC_CHECK_LIB(mncommon, _fini, [], [AC_MSG_FAILURE(libmncommon.so is required. Please find it at git@github.com:mkushnir/mncommon.git)])

AC_OUTPUT

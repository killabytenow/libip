dnl ###########################################################################
dnl ## configure.in
dnl ##
dnl ## This file gives all necessary information to Autoconf to build the
dnl ## libip configuration script.
dnl ##
dnl ## ------------------------------------------------------------------------
dnl ## libip - IP address manipulation library
dnl ##   (C) 2013 Gerardo García Peña <killabytenow@gmail.com>
dnl ##
dnl ##   This program is free software; you can redistribute it and/or modify
dnl ##   it under the terms of the GNU General Public License as published by
dnl ##   the Free Software Foundation; either version 2 of the License, or (at
dnl ##   your option) any later version.
dnl ##
dnl ##   This program is distributed in the hope that it will be useful, but
dnl ##   WITHOUT ANY WARRANTY; without even the implied warranty of
dnl ##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
dnl ##   General Public License for more details.
dnl ##
dnl ##   You should have received a copy of the GNU General Public License
dnl ##   along with this program; if not, write to the Free Software
dnl ##   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
dnl ##   02110-1301  USA
dnl ##
dnl ###########################################################################

AC_PREREQ(2.13)

dnl ---------------------------------------------------------------------------
dnl Set version
dnl ---------------------------------------------------------------------------

define(LIP_AC_VERSION_MAJOR,   1)
define(LIP_AC_VERSION_MINOR,   0)
define(LIP_AC_VERSION_RELEASE, 0)
define(LIP_AC_VERSION, LIP_AC_VERSION_MAJOR.LIP_AC_VERSION_MINOR.LIP_AC_VERSION_RELEASE)

dnl ---------------------------------------------------------------------------
dnl Basic configuration of autoconf+automake
dnl ---------------------------------------------------------------------------

AC_INIT([libip],LIP_AC_VERSION,[killabytenow@gmail.com],[libip])
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(autoconfig.h)

dnl ---------------------------------------------------------------------------
dnl Check essential tools and libraries
dnl ---------------------------------------------------------------------------

AC_PROG_INSTALL
AC_PROG_CC
AM_PROG_AS
AC_PROG_RANLIB
AC_C_INLINE
AC_C_STRINGIZE
AC_HEADER_STDC
AC_FUNC_STAT
AC_FUNC_VPRINTF

dnl ---------------------------------------------------------------------------
dnl Identify host platform and operating system
dnl ---------------------------------------------------------------------------

AC_C_BIGENDIAN
AC_CANONICAL_HOST

case "$host_cpu" in
sparc)
  # this CPU does not allow unaligned accesses
  ;;
i386|i486|i586|i686)
  ALLOW_UNALIGNED_16=1
  ALLOW_UNALIGNED_32=1
  ;;
*)
  AC_MSG_WARN([Unknown CPU '$host_cpu'.])
  ALLOW_UNALIGNED_16=1
  ALLOW_UNALIGNED_32=1
esac
if test "$ALLOW_UNALIGNED_16" ; then
  AC_DEFINE([ALLOW_UNALIGNED_16], [1], [Allows word unaligned memory accesses.])
fi
if test "$ALLOW_UNALIGNED_32" ; then
  AC_DEFINE([ALLOW_UNALIGNED_32], [1], [Allows dword unaligned memory accesses.])
fi

dnl ---------------------------------------------------------------------------
dnl Set compiler flags
dnl ---------------------------------------------------------------------------

dnl Try to detect compiler
if test "$GCC" = "yes"; then
  dnl Active warnings
  CFLAGS="$CFLAGS -Wall"
else
  case `$CC -version 2>&1` in
    *MIPSpro*)
      dnl This is a SGI MIPSpro compiler!
      CFLAGS="$CFLAGS -fullwarn"
      PIC_FLAG=-KPIC
      ;;
    *)
      dnl WTF!?
      AC_MSG_WARN("Unknown compiler.");
  esac
fi

dnl ---------------------------------------------------------------------------
dnl Basic configuration
dnl ---------------------------------------------------------------------------

AC_CHECK_SIZEOF(char)
AC_CHECK_SIZEOF(short int)
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long int)
AC_CHECK_SIZEOF(long long)
AC_CHECK_SIZEOF(void *)

dnl ---------------------------------------------------------------------------
dnl Check that libraries are ok
dnl ---------------------------------------------------------------------------

AC_CHECK_HEADERS([sys/socket.h      \
                  arpa/inet.h       \
                  netinet/in.h      ],
                 [],
                 AC_MSG_ERROR([Essential header file not found.]))

AC_CHECK_HEADERS([dlfcn.h], [], [])

AC_CHECK_TYPES([struct sockaddr_in],
               [], [I need at least a 'struct sockaddr_in'],
[
#include <sys/socket.h>
#include <netinet/in.h>
])
AC_CHECK_TYPES([struct sockaddr_in6], [], [],
[
#include <sys/socket.h>
#include <netinet/in.h>
])
AC_CHECK_TYPES([int8_t,   int16_t,   int32_t,   int64_t],   [], [], [#include <sys/types.h>])
AC_CHECK_TYPES([uint8_t,  uint16_t,  uint32_t,  uint64_t],  [], [], [#include <sys/types.h>])
AC_CHECK_TYPES([u_int8_t, u_int16_t, u_int32_t, u_int64_t], [], [], [#include <sys/types.h>])

dnl ---------------------------------------------------------------------------
dnl Set directories
dnl ---------------------------------------------------------------------------

dnl Create a definition with the default directory
define(LIP_AC_DEFAULT_PREFIX, /usr/local/AC_PACKAGE_TARNAME-AC_PACKAGE_VERSION)

dnl Set default prefix directory now because we need to write some dirs based
dnl on this value.
AC_PREFIX_DEFAULT(LIP_AC_DEFAULT_PREFIX)
test "$prefix" = "NONE" && prefix='LIP_AC_DEFAULT_PREFIX'
test "$exec_prefix" = "NONE" && exec_prefix='${prefix}'

dnl ---------------------------------------------------------------------------
dnl Tell Autoconf/Automake which files must be generated
dnl ---------------------------------------------------------------------------

AC_CONFIG_FILES([Makefile
                 libip.1])
AC_OUTPUT


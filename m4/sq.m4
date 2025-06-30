AC_DEFUN([AM_CHECK_SQ],
[
  AC_ARG_WITH([sq],
    [AS_HELP_STRING([--with-sq=PATH],
      [specify the path to the Sequoia 'sq' binary])],
    [sq_path="$withval"],
    [sq_path=""])


  SQ_PATH=""
  if test "x$sq_path" != "x" -a "x$sq_path" != "xyes" ; then
  AC_MSG_CHECKING([for Sequoia sq])
    if test -x "$sq_path"; then
      SQ_PATH="$sq_path"
      AC_MSG_RESULT([found at $sq_path])
    else
      AC_MSG_ERROR([specified sq binary at $sq_path is not executable])
    fi
  else
    # Search for sq in PATH
    AC_PATH_PROG([SQ_PATH], [sq])

    if test "x$SQ_PATH" = "x"; then
      AC_MSG_ERROR([Sequoia sq binary not found in PATH])
    fi
  fi

  # Define variables only if sq is found
  if test "x$SQ_PATH" != "x"; then
    AC_SUBST([SQ_PATH])
    AC_DEFINE_UNQUOTED([SQ_PATH], ["$SQ_PATH"], [Path to Sequoia sq binary])
    AC_DEFINE([WITH_SQ], [1], [Define to 1 if Sequoia sq binary is available])
  fi
])

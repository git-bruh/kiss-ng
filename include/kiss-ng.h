#ifndef KISS_NG_H
#define KISS_NG_H
#include <stdarg.h>
#include <stdbool.h>

enum kiss_log_level {
	KISS_LOG_INFO = 0,
	KISS_LOG_WARN,
	KISS_LOG_ERROR,
};

/* (KISS_COLOR_PRIMARY, "WARNING", KISS_COLOR_SECONDARY, "packagename",
 *  KISS_COLOR_CLEAR, "saving /etc/file as /etc/file.new") */
#define KISS_COLOR_PRIMARY ("\033[1;33m")
#define KISS_COLOR_SECONDARY ("\033[1;34m")
#define KISS_COLOR_CLEAR ("\033[m")

typedef void (*kiss_logfunc_t)(
  void *userp, enum kiss_log_level log_level, const char *fmt, va_list ap);

void
kiss_set_logfunc(void *userp, kiss_logfunc_t logfunc);

/* -1 for invalid `log_level`, 0 for success */
__attribute__((format(printf, 2, 3))) int
kiss_log(enum kiss_log_level log_level, const char *fmt, ...);

const char *
kiss_log_level_str(enum kiss_log_level log_level);
#endif

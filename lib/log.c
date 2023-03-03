#include "kiss-ng.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

static void(default_logfunc)(
  void *userp, enum kiss_log_level log_level, const char *fmt, va_list ap);

static struct {
	void *userp;
	kiss_logfunc_t logfunc;
} log_state = {
  .userp = NULL,
  .logfunc = default_logfunc,
};

void
kiss_set_logfunc(void *userp, kiss_logfunc_t logfunc) {
	log_state.userp = userp;
	log_state.logfunc = logfunc;
}

static void
default_logfunc(void *userp, enum kiss_log_level log_level,
  const char *const fmt, va_list ap) {
	(void) userp;

	if (isatty(STDERR_FILENO)) {
		fprintf(stderr, "%s%s%s ", KISS_COLOR_PRIMARY,
		  kiss_log_level_str(log_level), KISS_COLOR_CLEAR);
	} else {
		fprintf(stderr, "%s ", kiss_log_level_str(log_level));
	}

	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
}

int
kiss_log(enum kiss_log_level log_level, const char *const fmt, ...) {
	/* Check validity */
	if (!kiss_log_level_str(log_level)) {
		return -1;
	}

	va_list ap;
	va_start(ap, fmt);
	log_state.logfunc(log_state.userp, log_level, fmt, ap);
	va_end(ap);

	return 0;
}

const char *
kiss_log_level_str(enum kiss_log_level log_level) {
	switch (log_level) {
	case KISS_LOG_INFO:
		return "INFO";
	case KISS_LOG_WARN:
		return "WARN";
	case KISS_LOG_ERROR:
		return "ERROR";
	default:
		return NULL;
	}
}

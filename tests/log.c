#define _GNU_SOURCE
#include "kiss-ng.h"
#include "unity.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>

#define FORK_AND_COLLECT(infd, outfd, FORK_BODY)                               \
	do {                                                                       \
		switch (fork()) {                                                      \
		case -1:                                                               \
			abort();                                                           \
		case 0:                                                                \
			assert(dup2(outfd, infd) != -1);                                   \
			FORK_BODY                                                          \
                                                                               \
			exit(0);                                                           \
		default:                                                               \
			{                                                                  \
				int status;                                                    \
				assert(wait(&status) != -1);                                   \
				assert(WEXITSTATUS(status) == 0);                              \
				printf("%d\n", WEXITSTATUS(status));                           \
			}                                                                  \
		}                                                                      \
                                                                               \
		lseek(outfd, 0, SEEK_SET);                                              \
	} while (0)

void
setUp(void) {
}

void
tearDown(void) {
}

void
test_log_default(void) {
	int memfd = memfd_create("default", 0);

	assert(memfd != -1);

	FORK_AND_COLLECT(STDERR_FILENO, memfd, {
		kiss_log(KISS_LOG_WARN, "warning  !");
		kiss_log(KISS_LOG_ERROR, "error <");
		kiss_log(KISS_LOG_INFO, "informat i o n");
	});

	char buf[1024];
	read(memfd, buf, sizeof(buf));

	TEST_ASSERT_EQUAL_STRING(strtok(buf, "\n"), "WARN warning  !");
	TEST_ASSERT_EQUAL_STRING(strtok(NULL, "\n"), "ERROR error <");
	TEST_ASSERT_EQUAL_STRING(strtok(NULL, "\n"), "INFO informat i o n");
}

void
test_log_custom(void) {
}

int
main(void) {
	UNITY_BEGIN();
	RUN_TEST(test_log_default);
	RUN_TEST(test_log_custom);
	return UNITY_END();
}

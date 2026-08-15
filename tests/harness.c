#include "harness.h"

#include <stdarg.h>
#include <stdio.h>

static const char *current_test = "(none)";
static int checks_run;
static int checks_failed;
static int tests_run;
static int tests_failed;
static int failures_in_current_test;

void harness_begin(const char *name)
{
    /* Report the previous test before switching, so the log reads as one line
     * per test rather than a wall of passes. */
    if (tests_run > 0)
        printf("%s %s\n", failures_in_current_test == 0 ? "  ok  " : "FAILED", current_test);

    current_test = name;
    failures_in_current_test = 0;
    tests_run++;
}

void harness_pass(void)
{
    checks_run++;
}

void harness_fail(const char *file, int line, const char *fmt, ...)
{
    checks_run++;
    checks_failed++;
    if (failures_in_current_test == 0)
        tests_failed++;
    failures_in_current_test++;

    printf("  ---- %s:%d in %s\n       ", file, line, current_test);

    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}

int harness_report(void)
{
    if (tests_run > 0)
        printf("%s %s\n", failures_in_current_test == 0 ? "  ok  " : "FAILED", current_test);

    printf("\n%d tests, %d checks, %d failed\n", tests_run, checks_run, checks_failed);

    if (tests_failed == 0) {
        printf("PASS\n");
        return 0;
    }
    printf("FAIL (%d test%s)\n", tests_failed, tests_failed == 1 ? "" : "s");
    return 1;
}

/*
 * harness.h -- a very small test runner.
 *
 * There is no test framework here on purpose. The whole suite is assertions
 * over pure functions, and the only things a framework would add are a
 * dependency to install and a build step to explain. Roughly fifty lines cover
 * what is actually needed: name each test, report the first failing line with
 * both values, keep going after a failure, and exit non-zero at the end.
 */

#ifndef HARNESS_H
#define HARNESS_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Start a test. Everything checked after this is attributed to `name`. */
void harness_begin(const char *name);

/* Record a failure at a source location; keeps the run going. */
void harness_fail(const char *file, int line, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

void harness_pass(void);

/* Print the summary. Returns the process exit status: 0 when all passed. */
int harness_report(void);

/* Run one test function, printing its name. */
#define RUN(fn)              \
    do {                     \
        harness_begin(#fn);  \
        fn();                \
    } while (0)

#define CHECK(cond)                                                     \
    do {                                                                \
        if (cond) {                                                     \
            harness_pass();                                             \
        } else {                                                        \
            harness_fail(__FILE__, __LINE__, "expected: %s", #cond);    \
        }                                                               \
    } while (0)

#define CHECK_INT(actual, expected)                                          \
    do {                                                                     \
        long long harness_a = (long long)(actual);                           \
        long long harness_e = (long long)(expected);                         \
        if (harness_a == harness_e) {                                        \
            harness_pass();                                                  \
        } else {                                                             \
            harness_fail(__FILE__, __LINE__, "%s: expected %lld, got %lld",  \
                         #actual, harness_e, harness_a);                     \
        }                                                                    \
    } while (0)

#define CHECK_STR(actual, expected)                                            \
    do {                                                                       \
        const char *harness_a = (actual);                                      \
        const char *harness_e = (expected);                                    \
        if (harness_a != NULL && strcmp(harness_a, harness_e) == 0) {           \
            harness_pass();                                                    \
        } else {                                                               \
            harness_fail(__FILE__, __LINE__, "%s: expected \"%s\", got \"%s\"", \
                         #actual, harness_e,                                   \
                         harness_a != NULL ? harness_a : "(null)");            \
        }                                                                      \
    } while (0)

/* The suites, each defined in its own file. */
void test_packet_suite(void);
void test_stats_suite(void);
void test_csv_suite(void);

#endif /* HARNESS_H */

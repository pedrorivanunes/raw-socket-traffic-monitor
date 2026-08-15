/*
 * main.c -- the test runner.
 *
 * Every suite is a plain function. Adding one means writing it, declaring it
 * in harness.h and calling it here; there is no registration magic to explain
 * and nothing to install before `make test` works.
 */

#include <stdio.h>

#include "harness.h"

int main(void)
{
    printf("running the monitor test suite\n\n");

    test_packet_suite();
    test_stats_suite();
    test_csv_suite();

    return harness_report();
}

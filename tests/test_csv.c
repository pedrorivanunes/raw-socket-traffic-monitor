/*
 * test_csv.c -- escaping, and the round trip through a real file.
 *
 * The last test here is the one that matters. It writes a packet whose HTTP
 * request line contains a comma, reads the row back and counts the columns.
 * Before the fields were quoted that row came out with one column too many,
 * which is what "the info field can break the CSV" meant in practice.
 */

#define _DEFAULT_SOURCE

#include "harness.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "csv.h"
#include "packet.h"

static void leaves_a_plain_field_alone(void)
{
    char out[64];

    CHECK_INT(csv_escape_field("2026-08-15 12:00:00", out, sizeof(out)), 19);
    CHECK_STR(out, "2026-08-15 12:00:00");

    CHECK_INT(csv_escape_field("", out, sizeof(out)), 0);
    CHECK_STR(out, "");
}

static void quotes_a_field_containing_a_comma(void)
{
    char out[64];

    csv_escape_field("GET /a,b HTTP/1.1", out, sizeof(out));
    CHECK_STR(out, "\"GET /a,b HTTP/1.1\"");
}

/* Inside a quoted field a double quote is written twice. */
static void doubles_an_embedded_quote(void)
{
    char out[64];

    csv_escape_field("say \"hi\"", out, sizeof(out));
    CHECK_STR(out, "\"say \"\"hi\"\"\"");
}

static void quotes_a_field_containing_a_line_break(void)
{
    char out[64];

    csv_escape_field("first\nsecond", out, sizeof(out));
    CHECK_STR(out, "\"first\nsecond\"");

    csv_escape_field("first\rsecond", out, sizeof(out));
    CHECK_STR(out, "\"first\rsecond\"");
}

/* The return value is the length the field needs, so a caller can tell the
 * output was cut short. Whatever fits is still NUL-terminated. */
static void reports_the_length_it_needs(void)
{
    char out[8];

    size_t needed = csv_escape_field("0123456789", out, sizeof(out));
    CHECK_INT(needed, 10);
    CHECK_INT(strlen(out), 7);

    needed = csv_escape_field("a,b,c,d,e,f", out, sizeof(out));
    CHECK_INT(needed, 13); /* eleven characters plus the two quotes */
    CHECK(strlen(out) < sizeof(out));
}

/* Count the fields in a CSV line the way a parser would: a comma inside quotes
 * is data, not a separator. */
static int count_fields(const char *line)
{
    int fields = 1;
    bool in_quotes = false;

    for (const char *p = line; *p != '\0' && *p != '\n'; p++) {
        if (*p == '"') {
            if (in_quotes && p[1] == '"') {
                p++; /* an escaped quote, not the end of the field */
                continue;
            }
            in_quotes = !in_quotes;
        } else if (*p == ',' && !in_quotes) {
            fields++;
        }
    }
    return fields;
}

static void counts_fields_the_way_a_parser_would(void)
{
    CHECK_INT(count_fields("a,b,c"), 3);
    CHECK_INT(count_fields("a,\"b,c\",d"), 3);
    CHECK_INT(count_fields("a,\"b\"\"c\",d"), 3);
}

static void a_comma_in_the_summary_does_not_add_a_column(void)
{
    char directory[] = "/tmp/monitor_tests_XXXXXX";
    if (mkdtemp(directory) == NULL) {
        harness_fail(__FILE__, __LINE__, "could not create a temporary directory");
        return;
    }

    struct csv_output output;
    if (!csv_output_open(&output, directory)) {
        harness_fail(__FILE__, __LINE__, "could not open the CSV files in %s", directory);
        return;
    }

    struct packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.network = NETWORK_IPV4;
    pkt.transport = TRANSPORT_TCP;
    pkt.application = APP_HTTP;
    pkt.ip_protocol = 6;
    pkt.src_port = 51000;
    pkt.dst_port = 80;
    pkt.length = 200;
    snprintf(pkt.src_ip, sizeof(pkt.src_ip), "172.31.66.101");
    snprintf(pkt.dst_ip, sizeof(pkt.dst_ip), "93.184.216.34");
    snprintf(pkt.info, sizeof(pkt.info), "GET /a,b,c HTTP/1.1");

    csv_output_write(&output, "2026-08-15 12:00:00", &pkt);
    csv_output_close(&output);

    char path[512];
    snprintf(path, sizeof(path), "%s/application_layer.csv", directory);

    FILE *file = fopen(path, "r");
    CHECK(file != NULL);
    if (file != NULL) {
        char header[1024] = { 0 };
        char row[1024] = { 0 };

        CHECK(fgets(header, sizeof(header), file) != NULL);
        CHECK(fgets(row, sizeof(row), file) != NULL);

        /* The application file has six columns; two stray commas in the
         * summary used to turn that into eight. */
        CHECK_INT(count_fields(header), 6);
        CHECK_INT(count_fields(row), 6);
        CHECK(strstr(row, "\"GET /a,b,c HTTP/1.1\"") != NULL);

        fclose(file);
    }

    unlink(path);
    snprintf(path, sizeof(path), "%s/network_layer.csv", directory);
    unlink(path);
    snprintf(path, sizeof(path), "%s/transport_layer.csv", directory);
    unlink(path);
    rmdir(directory);
}

void test_csv_suite(void)
{
    RUN(leaves_a_plain_field_alone);
    RUN(quotes_a_field_containing_a_comma);
    RUN(doubles_an_embedded_quote);
    RUN(quotes_a_field_containing_a_line_break);
    RUN(reports_the_length_it_needs);
    RUN(counts_fields_the_way_a_parser_would);
    RUN(a_comma_in_the_summary_does_not_add_a_column);
}

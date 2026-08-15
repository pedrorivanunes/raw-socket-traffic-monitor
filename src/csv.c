/*
 * csv.c -- writing the capture files.
 */

#include "csv.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CSV_NETWORK_FILE "network_layer.csv"
#define CSV_TRANSPORT_FILE "transport_layer.csv"
#define CSV_APPLICATION_FILE "application_layer.csv"

#define CSV_NETWORK_HEADER "timestamp,protocol,src_ip,dst_ip,ip_protocol,info,length"
#define CSV_TRANSPORT_HEADER "timestamp,protocol,src_ip,src_port,dst_ip,dst_port,length"
#define CSV_APPLICATION_HEADER "timestamp,protocol,src_ip,dst_ip,info,length"

/* Worst case for an escaped field: every byte is a quote that has to be
 * doubled, plus the surrounding quotes and the terminator. */
#define CSV_FIELD_BUFFER (2 * PACKET_INFO_MAX + 3)

static bool field_needs_quoting(const char *field)
{
    return strpbrk(field, ",\"\r\n") != NULL;
}

size_t csv_escape_field(const char *field, char *out, size_t out_len)
{
    size_t needed = 0;
    size_t written = 0;

    /* Append one character, but only while there is room for it and for the
     * terminator. `needed` keeps counting either way, so the caller can tell
     * the output was cut short. */
#define EMIT(c)                              \
    do {                                     \
        if (written + 1 < out_len)           \
            out[written++] = (c);            \
        needed++;                            \
    } while (0)

    if (!field_needs_quoting(field)) {
        for (const char *p = field; *p != '\0'; p++)
            EMIT(*p);
    } else {
        EMIT('"');
        for (const char *p = field; *p != '\0'; p++) {
            if (*p == '"')
                EMIT('"'); /* a quote inside a quoted field is written twice */
            EMIT(*p);
        }
        /* Close the field even if the content had to be truncated, so a
         * clipped row is still a parseable row. */
        if (written + 1 >= out_len && out_len >= 2)
            written = out_len - 2;
        EMIT('"');
    }

#undef EMIT

    if (out_len > 0)
        out[written] = '\0';
    return needed;
}

bool csv_open(struct csv_writer *writer, const char *path, const char *header)
{
    bool is_new = (access(path, F_OK) != 0);

    writer->file = fopen(path, "a");
    if (writer->file == NULL) {
        perror(path);
        return false;
    }

    /* Line buffering, set before the first write. The original flushed after
     * every row so a reader could follow the capture live; this keeps that
     * property without a syscall per field. */
    setvbuf(writer->file, NULL, _IOLBF, 0);

    if (is_new)
        fprintf(writer->file, "%s\n", header);
    return true;
}

void csv_close(struct csv_writer *writer)
{
    if (writer->file != NULL) {
        fclose(writer->file);
        writer->file = NULL;
    }
}

void csv_write_row(struct csv_writer *writer, const char *const *fields, size_t count)
{
    if (writer->file == NULL)
        return;

    char escaped[CSV_FIELD_BUFFER];
    for (size_t i = 0; i < count; i++) {
        csv_escape_field(fields[i], escaped, sizeof(escaped));
        fputs(escaped, writer->file);
        if (i + 1 < count)
            fputc(',', writer->file);
    }
    fputc('\n', writer->file);
}

static bool open_in_directory(struct csv_writer *writer, const char *directory,
                              const char *name, const char *header)
{
    char path[512];

    if (directory != NULL && directory[0] != '\0')
        snprintf(path, sizeof(path), "%s/%s", directory, name);
    else
        snprintf(path, sizeof(path), "%s", name);

    return csv_open(writer, path, header);
}

bool csv_output_open(struct csv_output *output, const char *directory)
{
    memset(output, 0, sizeof(*output));

    if (!open_in_directory(&output->network, directory, CSV_NETWORK_FILE,
                           CSV_NETWORK_HEADER) ||
        !open_in_directory(&output->transport, directory, CSV_TRANSPORT_FILE,
                           CSV_TRANSPORT_HEADER) ||
        !open_in_directory(&output->application, directory, CSV_APPLICATION_FILE,
                           CSV_APPLICATION_HEADER)) {
        csv_output_close(output);
        return false;
    }
    return true;
}

void csv_output_close(struct csv_output *output)
{
    csv_close(&output->network);
    csv_close(&output->transport);
    csv_close(&output->application);
}

void csv_output_write(struct csv_output *output, const char *timestamp,
                      const struct packet *pkt)
{
    char length[32];
    char ip_protocol[16];
    char src_port[16];
    char dst_port[16];

    snprintf(length, sizeof(length), "%zu", pkt->length);
    snprintf(ip_protocol, sizeof(ip_protocol), "%u", pkt->ip_protocol);
    snprintf(src_port, sizeof(src_port), "%u", pkt->src_port);
    snprintf(dst_port, sizeof(dst_port), "%u", pkt->dst_port);

    /* ICMP is a network-layer event here, so it is named in this file rather
     * than left as a bare "IPv4". */
    const char *network_name = (pkt->transport == TRANSPORT_ICMP)
                                   ? "ICMP"
                                   : network_proto_name(pkt->network);

    const char *network_row[] = {
        timestamp, network_name, pkt->src_ip, pkt->dst_ip, ip_protocol, pkt->info, length,
    };
    csv_write_row(&output->network, network_row, 7);

    /* Below the network layer only IPv4 is decoded, so only IPv4 produces
     * transport and application rows. */
    if (pkt->network != NETWORK_IPV4)
        return;

    if (pkt->transport == TRANSPORT_TCP || pkt->transport == TRANSPORT_UDP) {
        const char *transport_row[] = {
            timestamp, transport_proto_name(pkt->transport), pkt->src_ip, src_port,
            pkt->dst_ip, dst_port, length,
        };
        csv_write_row(&output->transport, transport_row, 7);

        const char *application_row[] = {
            timestamp, app_proto_name(pkt->application), pkt->src_ip, pkt->dst_ip,
            pkt->info, length,
        };
        csv_write_row(&output->application, application_row, 6);
    } else if (pkt->transport == TRANSPORT_OTHER) {
        const char *transport_row[] = {
            timestamp, "other", pkt->src_ip, "0", pkt->dst_ip, "0", length,
        };
        csv_write_row(&output->transport, transport_row, 7);
    }
}

/*
 * csv.h -- the three capture files.
 *
 * The escaping here is the point of the module. Fields like the HTTP request
 * line are built from bytes off the wire, and a CSV has exactly two characters
 * that must not appear raw in a field: the separator and the newline. Writing
 * those straight into the file lets a remote host decide where the columns
 * fall, which is how a capture file ends up unparseable.
 */

#ifndef CSV_H
#define CSV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "packet.h"

struct csv_writer {
    FILE *file;
};

struct csv_output {
    struct csv_writer network;
    struct csv_writer transport;
    struct csv_writer application;
};

/*
 * Escape one field the way RFC 4180 describes: a field containing a comma, a
 * double quote, CR or LF is wrapped in double quotes, and any quote inside is
 * doubled. Everything else is copied as-is.
 *
 * Returns the length the escaped field needs, not counting the terminator. If
 * that is `out_len` or more the output is truncated, but it is always
 * NUL-terminated and, if the field was quoted, always properly closed.
 */
size_t csv_escape_field(const char *field, char *out, size_t out_len);

/* Append to `path`, writing `header` first if the file is new. */
bool csv_open(struct csv_writer *writer, const char *path, const char *header);
void csv_close(struct csv_writer *writer);

/* Write one row, escaping every field. */
void csv_write_row(struct csv_writer *writer, const char *const *fields, size_t count);

/*
 * Open the three capture files inside `directory` (NULL or "" means the
 * working directory). On failure any file already opened is closed again.
 */
bool csv_output_open(struct csv_output *output, const char *directory);
void csv_output_close(struct csv_output *output);

/* Record one packet across the files its layers reach. */
void csv_output_write(struct csv_output *output, const char *timestamp,
                      const struct packet *pkt);

#endif /* CSV_H */

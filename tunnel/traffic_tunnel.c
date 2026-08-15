/*
 * traffic_tunnel.c -- entry point for the tunnel.
 *
 * One side runs as the server: it brings up tun0, turns on forwarding and NAT,
 * and is the way out to the Internet. The other sides run as clients and point
 * their default route at it. The monitor then watches the server's tun0, where
 * every client's traffic passes in the clear.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tunnel.h"

#define ARG_SERVER_MODE "-s"
#define ARG_CLIENT_MODE "-c"

static void usage(const char *program)
{
    fprintf(stderr,
            "usage:\n"
            "  server: %s <interface> -s\n"
            "  client: %s <interface> -c <client-script.sh>\n"
            "\n"
            "<interface> is the real network device the tunnel rides on, not tun0.\n"
            "Both modes need root: they create a TUN device and open a raw socket.\n"
            "\n"
            "environment:\n"
            "  TUNNEL_VERBOSE=1   trace and hex-dump every packet\n",
            program, program);
}

int main(int argc, char *argv[])
{
    const char *verbose = getenv("TUNNEL_VERBOSE");
    tunnel_verbose = (verbose != NULL && strcmp(verbose, "0") != 0 && verbose[0] != '\0');

    if (argc < 3) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* The original compared only as many characters as the argument had, so a
     * bare "-" was accepted as "-s". */
    if (strcmp(argv[2], ARG_SERVER_MODE) == 0) {
        run_tunnel(1, argc, argv);
        return EXIT_SUCCESS;
    }

    if (strcmp(argv[2], ARG_CLIENT_MODE) == 0) {
        if (argc < 4) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        run_tunnel(0, argc, argv);
        return EXIT_SUCCESS;
    }

    usage(argv[0]);
    return EXIT_FAILURE;
}

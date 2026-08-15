/*
 * tunnel.c -- carrying IP packets between two hosts inside raw Ethernet frames.
 *
 * How it works: a TUN device gives the process every IP packet the kernel
 * routes into it. Each one is wrapped in an Ethernet header plus a dummy IP
 * header addressed to the peer, and pushed onto the local network with a raw
 * socket. The peer picks it up, checks the dummy destination, and writes the
 * inner packet back into its own TUN device, where the kernel routes it on.
 *
 * The outer addresses (192.168.255.1 and .10) are not real hosts; they are
 * just tags that let each side tell "this frame is for me" from the rest of
 * the broadcast traffic. Nothing routes them, so they never leave the segment.
 */

#include "tunnel.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* The kernel's own headers, not the glibc wrappers. struct ifreq and
 * IFF_PROMISC come from linux/if.h, and ETH_P_ALL has no portable equivalent.
 * Pulling in net/if.h or netinet/ether.h as well would redefine both. */
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>

#define MTU 1472

/* Size of the encapsulation the tunnel adds to every packet. */
#define OVERHEAD ((int)sizeof(struct eth_ip_s))

bool tunnel_verbose = false;

static void trace(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void trace(const char *fmt, ...)
{
    if (!tunnel_verbose)
        return;

    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

static void hexdump(const char *data, int len)
{
    if (!tunnel_verbose)
        return;

    for (int i = 0; i < len; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", (unsigned char)data[i]);
    }
    printf("\n");
}

int tun_alloc(const char *dev, int flags)
{
    struct ifreq ifr;
    const char *clone_device = "/dev/net/tun";

    int tun_fd = open(clone_device, O_RDWR);
    if (tun_fd == -1) {
        perror(clone_device);
        fprintf(stderr, "hint: the tunnel needs /dev/net/tun and CAP_NET_ADMIN\n");
        exit(EXIT_FAILURE);
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = (short)flags;
    if (*dev)
        snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);

    if (ioctl(tun_fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(tun_fd);
        exit(EXIT_FAILURE);
    }

    printf("[tunnel] created %s\n", dev);
    return tun_fd;
}

int tun_read(int tun_fd, char *buffer, int length)
{
    int bytes_read = (int)read(tun_fd, buffer, (size_t)length);
    if (bytes_read == -1) {
        perror("read(tun)");
        exit(EXIT_FAILURE);
    }
    return bytes_read;
}

int tun_write(int tun_fd, char *buffer, int length)
{
    int bytes_written = (int)write(tun_fd, buffer, (size_t)length);
    if (bytes_written == -1) {
        perror("write(tun)");
        exit(EXIT_FAILURE);
    }
    return bytes_written;
}

/*
 * Run the shell script that gives the interface its address. The server script
 * also turns on forwarding and NAT; a client script replaces the default route
 * so everything leaves through the tunnel.
 *
 * This used to take the server flag as well and pick the script itself, which
 * meant the second argument was only allowed to be NULL when the first one was
 * set -- a rule nothing enforced and static analysis rightly complained about.
 * Choosing the script is the caller's job now, and this function has one
 * parameter with one meaning.
 */
static void run_setup_script(const char *script)
{
    char path[100];

    if (script == NULL) {
        fprintf(stderr, "no setup script to run\n");
        exit(EXIT_FAILURE);
    }

    /* The original compared with `>` and then used strncpy, which together
     * allowed a name of exactly sizeof(path) to be copied without a
     * terminator. snprintf always terminates, and the check now leaves room
     * for it. */
    if (strlen(script) >= sizeof(path)) {
        fprintf(stderr, "setup script path '%s' is too long\n", script);
        exit(EXIT_FAILURE);
    }
    snprintf(path, sizeof(path), "%s", script);

    char *const args[] = { path, NULL };

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        execv(path, args);
        perror(path);
        _exit(EXIT_FAILURE);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("[tunnel] %s completed\n", path);
    } else {
        fprintf(stderr, "[tunnel] %s failed\n", path);
        exit(EXIT_FAILURE);
    }
}

/*
 * The checksum of the dummy IP header.
 *
 * The bytes have to be read as unsigned. Reading them through a plain `char`,
 * which is signed on x86, sign-extends anything above 0x7F -- and the
 * addresses this header carries start with 192 and 255, so it happened on
 * every packet. Nothing on the receiving side verifies this field, so the
 * error was invisible, but it was still producing a wrong checksum.
 */
static uint16_t ip_checksum(const void *header)
{
    const unsigned char *bytes = header;
    unsigned long sum = 0;

    for (int i = 0; i < 20; i += 2)
        sum += ((unsigned long)bytes[i] << 8) | (unsigned long)bytes[i + 1];

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)(~sum & 0xFFFF);
}

void run_tunnel(int server, int argc, char *argv[])
{
    /* The peer never learns anyone's real MAC, so these are fixed. The frame
     * goes out to the broadcast address and each side filters on the dummy IP. */
    const uint8_t broadcast_mac[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    const uint8_t src_mac[6] = { 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };

    /* The tag this side answers to, and the one it sends to. */
    const uint8_t local_tag[4] = { 192, 168, 255, server ? 1 : 10 };
    const uint8_t peer_tag[4] = { 192, 168, 255, server ? 10 : 1 };

    char buf[ETH_LEN];
    struct eth_ip_s *hdr = (struct eth_ip_s *)buf;
    char *payload = buf + sizeof(struct eth_ip_s);

    struct ifreq if_index, if_flags;
    char interface[IFNAMSIZ];

    if (argc < 3) {
        fprintf(stderr, "no interface given\n");
        exit(EXIT_FAILURE);
    }

    /* This was a plain strcpy into a 16-byte buffer. An interface name longer
     * than that -- and the kernel limit is exactly 16 -- overflowed the stack. */
    if (strlen(argv[1]) >= sizeof(interface)) {
        fprintf(stderr, "interface name '%s' is too long\n", argv[1]);
        exit(EXIT_FAILURE);
    }
    snprintf(interface, sizeof(interface), "%s", argv[1]);

    int tun_fd = tun_alloc("tun0", IFF_TUN | IFF_NO_PI);

    printf("[tunnel] mode: %s, carrier interface: %s\n",
           server ? "server" : "client", interface);

    int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd == -1) {
        perror("socket(AF_PACKET)");
        exit(EXIT_FAILURE);
    }

    /* Promiscuous mode: the frames carry a broadcast destination, but the
     * switch or bridge in between may still filter, and the peer's replies are
     * not addressed to this machine's real MAC. */
    memset(&if_flags, 0, sizeof(if_flags));
    snprintf(if_flags.ifr_name, IFNAMSIZ, "%s", interface);
    if (ioctl(sock_fd, SIOCGIFFLAGS, &if_flags) < 0) {
        perror("ioctl(SIOCGIFFLAGS)");
        exit(EXIT_FAILURE);
    }
    if_flags.ifr_flags |= IFF_PROMISC;
    if (ioctl(sock_fd, SIOCSIFFLAGS, &if_flags) < 0) {
        perror("ioctl(SIOCSIFFLAGS)");
        exit(EXIT_FAILURE);
    }

    memset(&if_index, 0, sizeof(if_index));
    snprintf(if_index.ifr_name, IFNAMSIZ, "%s", interface);
    if (ioctl(sock_fd, SIOCGIFINDEX, &if_index) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        exit(EXIT_FAILURE);
    }

    /* This struct used to be left uninitialised apart from two fields, so
     * sll_family and sll_protocol were whatever the stack happened to hold. */
    struct sockaddr_ll socket_address;
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_IP);
    socket_address.sll_ifindex = if_index.ifr_ifindex;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, broadcast_mac, 6);

    /* The server's script is fixed; a client is told which one to use. main()
     * has already rejected client mode without that argument. */
    run_setup_script(server ? SERVER_SCRIPT : (argc >= 4 ? argv[3] : NULL));

    printf("[tunnel] running\n");
    fflush(stdout);

    for (;;) {
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(tun_fd, &readable);
        FD_SET(sock_fd, &readable);

        int max_fd = tun_fd > sock_fd ? tun_fd : sock_fd;
        if (select(max_fd + 1, &readable, NULL, NULL, NULL) < 0) {
            perror("select");
            break;
        }

        /* Outbound: a packet the kernel routed into tun0. */
        if (FD_ISSET(tun_fd, &readable)) {
            memset(buf, 0, sizeof(buf));

            int size = tun_read(tun_fd, payload, MTU);
            trace("[tunnel] read %d bytes from tun0\n", size);
            hexdump(payload, size);

            memcpy(hdr->ethernet.dst_addr, broadcast_mac, 6);
            memcpy(hdr->ethernet.src_addr, src_mac, 6);
            hdr->ethernet.eth_type = htons(ETH_P_IP);

            hdr->ip.ver = 0x45;
            hdr->ip.tos = 0x00;
            hdr->ip.len = htons((uint16_t)(size + sizeof(struct ip_hdr)));
            hdr->ip.id = 0;
            hdr->ip.off = 0;
            hdr->ip.ttl = 50;
            hdr->ip.proto = 0xFF;
            hdr->ip.sum = 0;
            memcpy(hdr->ip.src, local_tag, 4);
            memcpy(hdr->ip.dst, peer_tag, 4);
            hdr->ip.sum = htons(ip_checksum(&hdr->ip));

            if (sendto(sock_fd, buf, (size_t)size + sizeof(struct eth_ip_s), 0,
                       (struct sockaddr *)&socket_address,
                       sizeof(socket_address)) < 0)
                perror("sendto");
            else
                trace("[tunnel] forwarded %d bytes to the peer\n", size);
        }

        /* Inbound: a frame off the wire, which may or may not be ours. */
        if (FD_ISSET(sock_fd, &readable)) {
            ssize_t size = recv(sock_fd, buf, sizeof(buf), 0);
            if (size < 0) {
                perror("recv");
                continue;
            }

            /* Anything shorter than the encapsulation cannot be a tunnel frame,
             * and reading its header would run off the end of what arrived. */
            if (size < OVERHEAD)
                continue;
            if (hdr->ethernet.eth_type != htons(ETH_P_IP))
                continue;
            if (memcmp(hdr->ip.dst, local_tag, 4) != 0)
                continue;

            /* The inner packet is what is left after the encapsulation. The
             * original passed the whole frame length here, so every write also
             * handed the kernel 34 bytes of whatever followed in the buffer. */
            int inner = (int)size - OVERHEAD;
            hexdump(payload, inner);
            tun_write(tun_fd, payload, inner);
            trace("[tunnel] delivered %d bytes to tun0\n", inner);
        }
    }

    close(sock_fd);
    close(tun_fd);
}

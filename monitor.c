// Pedro Nunes
// monitor.c
// Monitor de trafego de rede com raw sockets (Linux/VirtualBox)
// Captura IPv4/IPv6/TCP/UDP/ICMP em interfaces Ethernet OU TUN (tun0),
// gera 3 CSVs (camada_internet.csv, camada_transporte.csv, camada_aplicacao.csv)
// e imprime estatisticas por cliente (172.31.66.0/24) incluindo "conexoes" por porta.

// Necessario para expor os campos BSD de struct tcphdr/udphdr (source, dest, ...)
// na glibc. Sem isso, o codigo aparece com erro de "tipo incompleto" em
// editores/compiladores em modo ISO estrito. Deve vir ANTES de qualquer #include.
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <netpacket/packet.h>   // versao user-space de if_packet
#include <linux/if_ether.h>     // ETH_P_*, struct ethhdr (ok usar)
#include <net/if.h>

#define BUF_SIZE 65536

// Limites simples para estatisticas por cliente
#define MAX_CLIENTES 64
#define MAX_REMOTOS  256
#define MAX_FLOWS    256

// Contadores globais
struct {
    unsigned long ipv4, ipv6, icmp, outro_rede;
    unsigned long tcp, udp, outro_transp;
    unsigned long http, dhcp, dns, ntp, outro_aplic;
} stats = {0};

// Cabecalho DNS (12 bytes)
struct dns_hdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed));

// Estatísticas por fluxo (conexão) cliente↔remoto
struct FlowStats {
    int proto;              // IPPROTO_TCP, IPPROTO_UDP, etc.
    uint16_t lport;         // porta do cliente (túnel)
    uint16_t rport;         // porta do remoto
    unsigned long pacotes;
    unsigned long bytes;
};

// Estatisticas por IP remoto para cada cliente
struct RemotoStats {
    char ip_remoto[INET6_ADDRSTRLEN];
    unsigned long pacotes;
    unsigned long bytes;
    unsigned long tcp;
    unsigned long udp;
    unsigned long icmp;

    unsigned long conexoes;        // quantidade de fluxos distintos
    struct FlowStats flows[MAX_FLOWS];
    int num_flows;
};

// Estatisticas por cliente (IP da rede tunel)
struct ClienteStats {
    char ip_cliente[INET6_ADDRSTRLEN];
    struct RemotoStats remotos[MAX_REMOTOS];
    int num_remotos;
};

static struct ClienteStats clientes[MAX_CLIENTES];
static int num_clientes = 0;

// ---------------------------- Utilidades gerais ----------------------------

static void timestamp_now(char *buf, size_t len) {
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", tm_info);
}

static FILE *open_csv(const char *path, const char *header_line) {
    int exists = (access(path, F_OK) == 0); // OBS: F_OK em alguns sistemas
    if (access(path, F_OK) != 0) exists = 0;
    FILE *f = fopen(path, "a");
    if (!f) { perror(path); return NULL; }
    if (!exists) { fprintf(f, "%s\n", header_line); fflush(f); }
    return f;
}

// Detecta protocolo de aplicação pelas portas
static const char *detect_app(int l4_proto, uint16_t sport, uint16_t dport) {
    if (l4_proto == IPPROTO_TCP) {
        if (sport == 80 || dport == 80 || sport == 8080 || dport == 8080 ||
            sport == 443 || dport == 443) return "HTTP";
    }
    if (l4_proto == IPPROTO_TCP || l4_proto == IPPROTO_UDP) {
        if (sport == 53 || dport == 53 || sport == 5353 || dport == 5353) return "DNS";
    }
    if (l4_proto == IPPROTO_UDP) {
        if ((sport == 67 && dport == 68) || (sport == 68 && dport == 67)) return "DHCP";
        if (sport == 123 || dport == 123) return "NTP";
    }
    return "outro";
}

// ------------------------ Estatisticas por cliente -------------------------

static int is_tun_cliente_ipv4(const char *ip) {
    return strncmp(ip, "172.31.66.", 10) == 0;
}

static struct ClienteStats *find_or_add_cliente(const char *ip_cliente) {
    for (int i = 0; i < num_clientes; i++)
        if (strcmp(clientes[i].ip_cliente, ip_cliente) == 0) return &clientes[i];
    if (num_clientes >= MAX_CLIENTES) return NULL;
    struct ClienteStats *c = &clientes[num_clientes++];
    memset(c, 0, sizeof(*c));
    strncpy(c->ip_cliente, ip_cliente, sizeof(c->ip_cliente) - 1);
    return c;
}

static struct RemotoStats *find_or_add_remoto(struct ClienteStats *cli, const char *ip_remoto) {
    for (int j = 0; j < cli->num_remotos; j++)
        if (strcmp(cli->remotos[j].ip_remoto, ip_remoto) == 0) return &cli->remotos[j];
    if (cli->num_remotos >= MAX_REMOTOS) return NULL;
    struct RemotoStats *r = &cli->remotos[cli->num_remotos++];
    memset(r, 0, sizeof(*r));
    strncpy(r->ip_remoto, ip_remoto, sizeof(r->ip_remoto) - 1);
    return r;
}

static struct FlowStats *find_or_add_flow(struct RemotoStats *r, int proto, uint16_t lport, uint16_t rport) {
    for (int i = 0; i < r->num_flows; i++) {
        struct FlowStats *f = &r->flows[i];
        if (f->proto == proto && f->lport == lport && f->rport == rport) return f;
    }
    if (r->num_flows >= MAX_FLOWS) return NULL;
    struct FlowStats *f = &r->flows[r->num_flows++];
    memset(f, 0, sizeof(*f));
    f->proto = proto; f->lport = lport; f->rport = rport;
    r->conexoes++;
    return f;
}

static void update_cliente_stats(const char *src_ip, const char *dst_ip,
                                 int l4_proto, uint16_t sport, uint16_t dport,
                                 size_t bytes)
{
    const char *ip_cliente = NULL, *ip_remoto = NULL;
    uint16_t lport = 0, rport = 0;

    if (is_tun_cliente_ipv4(src_ip) && !is_tun_cliente_ipv4(dst_ip)) {
        ip_cliente = src_ip; ip_remoto = dst_ip; lport = sport; rport = dport;
    } else if (is_tun_cliente_ipv4(dst_ip) && !is_tun_cliente_ipv4(src_ip)) {
        ip_cliente = dst_ip; ip_remoto = src_ip; lport = dport; rport = sport;
    } else return;

    struct ClienteStats *cli = find_or_add_cliente(ip_cliente); if (!cli) return;
    struct RemotoStats *r = find_or_add_remoto(cli, ip_remoto); if (!r) return;

    r->pacotes++; r->bytes += bytes;
    if (l4_proto == IPPROTO_TCP) r->tcp++;
    else if (l4_proto == IPPROTO_UDP) r->udp++;
    else if (l4_proto == IPPROTO_ICMP) r->icmp++;

    if (l4_proto == IPPROTO_TCP || l4_proto == IPPROTO_UDP) {
        struct FlowStats *f = find_or_add_flow(r, l4_proto, lport, rport);
        if (f) { f->pacotes++; f->bytes += bytes; }
    }
}

// ---------------------- Decodificacaoo de aplicacao ------------------------

static void build_http_info(const unsigned char *payload, size_t app_len,
                            char *info, size_t info_len)
{
    if (app_len == 0 || info_len == 0) { if (info_len) info[0] = '\0'; return; }
    size_t max = app_len; if (max > info_len - 1) max = info_len - 1;
    size_t i; for (i = 0; i < max; i++) {
        unsigned char c = payload[i];
        if (c == '\r' || c == '\n') break;
        if (c < 0x20 && c != '\t') break;
        info[i] = (char)c;
    }
    info[i] = '\0'; if (i == 0) { strncpy(info, "-", info_len); info[info_len-1] = '\0'; }
}

static void build_dns_info(const unsigned char *payload, size_t app_len,
                           char *info, size_t info_len)
{
    if (app_len < sizeof(struct dns_hdr)) { strncpy(info, "-", info_len); info[info_len-1] = '\0'; return; }
    const struct dns_hdr *dns = (const struct dns_hdr *)payload;
    uint16_t id = ntohs(dns->id), flags = ntohs(dns->flags), qdcount = ntohs(dns->qdcount);
    int qr = (flags & 0x8000) ? 1 : 0;
    char name[128]; name[0] = '\0';
    size_t offset = sizeof(struct dns_hdr), name_pos = 0;
    if (qdcount > 0) {
        while (offset < app_len) {
            uint8_t len = payload[offset]; if (len == 0) { offset++; break; }
            offset++; if (offset + len > app_len) break;
            if (name_pos > 0 && name_pos < sizeof(name)-1) name[name_pos++]='.';
            for (uint8_t i=0;i<len && name_pos < sizeof(name)-1;i++) name[name_pos++] = (char)payload[offset+i];
            offset += len;
        }
        name[name_pos] = '\0';
    }
    const char *tipo = qr ? "resp" : "query";
    if (name[0] == '\0') snprintf(info, info_len, "%s id=%u", tipo, id);
    else snprintf(info, info_len, "%s id=%u name=%s", tipo, id, name);
}

static void build_dhcp_info(const unsigned char *payload, size_t app_len,
                            char *info, size_t info_len)
{
    if (app_len < 240) { strncpy(info, "-", info_len); info[info_len-1]='\0'; return; }
    size_t offset = 240; const uint8_t *p = payload; uint8_t msg_type=0;
    while (offset + 2 <= app_len) {
        uint8_t opt = p[offset]; if (opt == 0xFF) break; if (opt == 0x00) { offset++; continue; }
        uint8_t len = p[offset+1]; if (offset + 2 + len > app_len) break;
        if (opt == 53 && len >= 1) { msg_type = p[offset+2]; break; }
        offset += 2 + len;
    }
    const char *tipo = "desconhecido";
    if (msg_type==1) tipo="DISCOVER"; else if (msg_type==2) tipo="OFFER";
    else if (msg_type==3) tipo="REQUEST"; else if (msg_type==4) tipo="DECLINE";
    else if (msg_type==5) tipo="ACK"; else if (msg_type==6) tipo="NAK";
    else if (msg_type==7) tipo="RELEASE"; else if (msg_type==8) tipo="INFORM";
    if (msg_type==0) { strncpy(info,"-",info_len); info[info_len-1]='\0'; }
    else snprintf(info, info_len, "type=%s(%u)", tipo, msg_type);
}

static void build_ntp_info(const unsigned char *payload, size_t app_len,
                           char *info, size_t info_len)
{
    if (app_len < 1) { strncpy(info, "-", info_len); info[info_len-1]='\0'; return; }
    uint8_t b = payload[0];
    snprintf(info, info_len, "LI=%d,VN=%d,Mode=%d", (b>>6)&3, (b>>3)&7, b&7);
}

// --------------------------- Impressao de stats ----------------------------

static const char *proto_name(int proto) {
    if (proto == IPPROTO_TCP) return "TCP";
    if (proto == IPPROTO_UDP) return "UDP";
    if (proto == IPPROTO_ICMP) return "ICMP";
    return "OUTRO";
}

static void print_stats(void) {
    printf("\n=== Monitor de Tráfego de Rede (RAW IPv4/IPv6 – Linux/WSL) ===\n");
    printf("Camada Internet (rede):\n");
    printf("  IPv4   : %lu\n", stats.ipv4);
    printf("  IPv6   : %lu\n", stats.ipv6);
    printf("  ICMP   : %lu\n", stats.icmp);
    printf("  outro  : %lu\n", stats.outro_rede);

    printf("\nCamada Transporte:\n");
    printf("  TCP    : %lu\n", stats.tcp);
    printf("  UDP    : %lu\n", stats.udp);
    printf("  outro  : %lu\n", stats.outro_transp);

    printf("\nCamada Aplicação:\n");
    printf("  HTTP   : %lu\n", stats.http);
    printf("  DHCP   : %lu\n", stats.dhcp);
    printf("  DNS    : %lu\n", stats.dns);
    printf("  NTP    : %lu\n", stats.ntp);
    printf("  outro  : %lu\n", stats.outro_aplic);

    printf("\n=== Estatísticas por cliente (rede túnel 172.31.66.0/24) ===\n");
    for (int i = 0; i < num_clientes; i++) {
        struct ClienteStats *c = &clientes[i];
        printf("Cliente %s:\n", c->ip_cliente);
        for (int j = 0; j < c->num_remotos; j++) {
            struct RemotoStats *r = &c->remotos[j];
            printf("  Remoto %s: pacotes=%lu, bytes=%lu, TCP=%lu, UDP=%lu, ICMP=%lu, conexoes=%lu\n",
                   r->ip_remoto, r->pacotes, r->bytes, r->tcp, r->udp, r->icmp, r->conexoes);
            for (int k = 0; k < r->num_flows; k++) {
                struct FlowStats *f = &r->flows[k];
                printf("    %s porta_local=%u -> porta_remota=%u: pacotes=%lu, bytes=%lu\n",
                       proto_name(f->proto), f->lport, f->rport, f->pacotes, f->bytes);
            }
        }
    }
    printf("\n(Pressione Ctrl+C para parar)\n");
    fflush(stdout);
}

// ---------------------- Deteccao de L2 (Ethernet / TUN / SLL) --------------

static int parse_l2(const unsigned char *buf, size_t len, int is_tun,
                    uint16_t *proto, size_t *l2_len)
{
    if (len < 1) return -1;

    // 1) Caso mais comum no TUN: pacote IP "nu", sem L2
    uint8_t v0 = buf[0] >> 4;
    if (v0 == 4) { *proto = ETH_P_IP;   *l2_len = 0;  return 0; }
    if (v0 == 6) { *proto = ETH_P_IPV6; *l2_len = 0;  return 0; }

    // 2) Ethernet "normal"
    if (!is_tun) {
        if (len < sizeof(struct ethhdr)) return -1;
        const struct ethhdr *eth = (const struct ethhdr *)buf;
        *proto  = ntohs(eth->h_proto);
        *l2_len = sizeof(struct ethhdr);
        return 0;
    }

    // 3) Cooked SLL v1 (16 bytes): protocolo nos bytes 14..15
    if (len >= 16) {
        uint16_t p = ntohs(*(const uint16_t *)(buf + 14));
        if (p == ETH_P_IP || p == ETH_P_IPV6) { *proto = p; *l2_len = 16; return 0; }
    }

    // 4) Cooked SLL v2 (20 bytes): protocolo nos bytes 0..1
    if (len >= 20) {
        uint16_t p = ntohs(*(const uint16_t *)(buf + 0));
        if (p == ETH_P_IP || p == ETH_P_IPV6) { *proto = p; *l2_len = 20; return 0; }
    }

    // 5) Tentativa final: se apos 16 bytes parecer IP/IPv6, assuma SLL v1
    if (len > 16) {
        uint8_t v = buf[16] >> 4;
        if (v == 4) { *proto = ETH_P_IP;   *l2_len = 16; return 0; }
        if (v == 6) { *proto = ETH_P_IPV6; *l2_len = 16; return 0; }
    }

    return -1;
}

// --------------------------------- main ------------------------------------

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Uso: %s <interface>\nExemplo: %s tun0\n", argv[0], argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    int is_tun = (strncmp(ifname, "tun", 3) == 0);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket(AF_PACKET)"); return 1; }

    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) { perror("if_nametoindex"); close(sock); return 1; }

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family   = AF_PACKET;
    addr.sll_ifindex  = ifindex;
    addr.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(sock); return 1;
    }

    FILE *csv_rede = open_csv("camada_internet.csv",
        "timestamp,protocolo,ip_origem,ip_destino,protocolo_superior,info,tamanho");
    FILE *csv_trans = open_csv("camada_transporte.csv",
        "timestamp,protocolo,ip_origem,porta_origem,ip_destino,porta_destino,tamanho");
    FILE *csv_app = open_csv("camada_aplicacao.csv",
        "timestamp,protocolo,ip_origem,ip_destino,info,tamanho");
    if (!csv_rede || !csv_trans || !csv_app) {
        if (csv_rede) fclose(csv_rede);
        if (csv_trans) fclose(csv_trans);
        if (csv_app) fclose(csv_app);
        close(sock); return 1;
    }

    printf("=== Monitor de Trafego (raw sockets) ===\n");
    printf("Interface: %s\n", ifname);
    printf("Gerando: camada_internet.csv, camada_transporte.csv, camada_aplicacao.csv\n");

    unsigned char buffer[BUF_SIZE];
    time_t last_print = 0;

    while (1) {
        ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len < 0) { if (errno == EINTR) continue; perror("recvfrom"); break; }
        size_t frame_len = (size_t)len; if (frame_len == 0) continue;

        char ts[32]; timestamp_now(ts, sizeof(ts));

        uint16_t l2_proto = 0; size_t l2_len = 0;
        if (parse_l2(buffer, frame_len, is_tun, &l2_proto, &l2_len) < 0) {
            stats.outro_rede++; continue;
        }

        char src_ip[INET6_ADDRSTRLEN] = "-";
        char dst_ip[INET6_ADDRSTRLEN] = "-";
        int l4_proto = 0; uint16_t sport = 0, dport = 0;
        const char *rede_nome = "outro"; size_t camada_len = frame_len;

        if (l2_proto == ETH_P_IP) {                 // ===== IPv4 =====
            if (frame_len < l2_len + sizeof(struct iphdr)) continue;
            struct iphdr *ip = (struct iphdr *)(buffer + l2_len);
            l4_proto = ip->protocol;

            unsigned int iphdr_len = ip->ihl * 4; if (iphdr_len < 20) continue;
            if (frame_len < l2_len + iphdr_len) continue;

            struct in_addr saddr = { ip->saddr }, daddr = { ip->daddr };
            inet_ntop(AF_INET, &saddr, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, &daddr, dst_ip, sizeof(dst_ip));

            camada_len = ntohs(ip->tot_len);

            char info_rede[128]; strncpy(info_rede, "-", sizeof(info_rede)); info_rede[sizeof(info_rede)-1]='\0';
            if (ip->protocol == IPPROTO_ICMP) {
                rede_nome = "ICMP"; stats.icmp++;
                if (frame_len >= l2_len + iphdr_len + sizeof(struct icmphdr)) {
                    struct icmphdr *icmp = (struct icmphdr *)(buffer + l2_len + iphdr_len);
                    snprintf(info_rede, sizeof(info_rede), "type=%u,code=%u", icmp->type, icmp->code);
                }
                update_cliente_stats(src_ip, dst_ip, IPPROTO_ICMP, 0, 0, camada_len);
            } else {
                rede_nome = "IPv4"; stats.ipv4++;
            }
            fprintf(csv_rede, "%s,%s,%s,%s,%d,%s,%zu\n",
                    ts, rede_nome, src_ip, dst_ip, ip->protocol, info_rede, camada_len);
            fflush(csv_rede);

            size_t l4_offset = l2_len + iphdr_len;
            if (frame_len >= l4_offset) {
                unsigned char *l4 = buffer + l4_offset;

                if (l4_proto == IPPROTO_TCP && frame_len >= l4_offset + sizeof(struct tcphdr)) {
                    struct tcphdr *tcp = (struct tcphdr *)l4;
                    sport = ntohs(tcp->source); dport = ntohs(tcp->dest); stats.tcp++;
                    fprintf(csv_trans, "%s,TCP,%s,%u,%s,%u,%zu\n", ts, src_ip, sport, dst_ip, dport, camada_len);
                    fflush(csv_trans);
                    update_cliente_stats(src_ip, dst_ip, IPPROTO_TCP, sport, dport, camada_len);

                    const char *app = detect_app(l4_proto, sport, dport);
                    char info_app[256]; strncpy(info_app, "-", sizeof(info_app)); info_app[sizeof(info_app)-1]='\0';
                    unsigned int tcp_hdr_len = tcp->doff * 4; if (tcp_hdr_len < 20) tcp_hdr_len = 20;
                    size_t app_offset = l4_offset + tcp_hdr_len;
                    if (frame_len > app_offset) {
                        const unsigned char *app_payload = buffer + app_offset;
                        size_t app_len = frame_len - app_offset;
                        if (strcmp(app, "HTTP") == 0) { stats.http++; build_http_info(app_payload, app_len, info_app, sizeof(info_app)); }
                        else if (strcmp(app, "DNS") == 0) { stats.dns++; build_dns_info(app_payload, app_len, info_app, sizeof(info_app)); }
                        else { stats.outro_aplic++; }
                    } else {
                        if (strcmp(app, "HTTP") == 0) stats.http++;
                        else if (strcmp(app, "DNS") == 0) stats.dns++;
                        else stats.outro_aplic++;
                    }
                    fprintf(csv_app, "%s,%s,%s,%s,%s,%zu\n", ts, app, src_ip, dst_ip, info_app, camada_len);
                    fflush(csv_app);

                } else if (l4_proto == IPPROTO_UDP && frame_len >= l4_offset + sizeof(struct udphdr)) {
                    struct udphdr *udp = (struct udphdr *)l4;
                    sport = ntohs(udp->source); dport = ntohs(udp->dest); stats.udp++;
                    fprintf(csv_trans, "%s,UDP,%s,%u,%s,%u,%zu\n", ts, src_ip, sport, dst_ip, dport, camada_len);
                    fflush(csv_trans);
                    update_cliente_stats(src_ip, dst_ip, IPPROTO_UDP, sport, dport, camada_len);

                    const char *app = detect_app(l4_proto, sport, dport);
                    char info_app[256]; strncpy(info_app, "-", sizeof(info_app)); info_app[sizeof(info_app)-1]='\0';
                    size_t app_offset = l4_offset + sizeof(struct udphdr);
                    if (frame_len > app_offset) {
                        const unsigned char *app_payload = buffer + app_offset;
                        size_t app_len = frame_len - app_offset;
                        if (strcmp(app, "DNS") == 0) { stats.dns++; build_dns_info(app_payload, app_len, info_app, sizeof(info_app)); }
                        else if (strcmp(app, "DHCP") == 0) { stats.dhcp++; build_dhcp_info(app_payload, app_len, info_app, sizeof(info_app)); }
                        else if (strcmp(app, "NTP") == 0) { stats.ntp++; build_ntp_info(app_payload, app_len, info_app, sizeof(info_app)); }
                        else if (strcmp(app, "HTTP") == 0) { stats.http++; build_http_info(app_payload, app_len, info_app, sizeof(info_app)); }
                        else { stats.outro_aplic++; }
                    } else {
                        if (strcmp(app, "DNS") == 0) stats.dns++;
                        else if (strcmp(app, "DHCP") == 0) stats.dhcp++;
                        else if (strcmp(app, "NTP") == 0) stats.ntp++;
                        else if (strcmp(app, "HTTP") == 0) stats.http++;
                        else stats.outro_aplic++;
                    }
                    fprintf(csv_app, "%s,%s,%s,%s,%s,%zu\n", ts, app, src_ip, dst_ip, info_app, camada_len);
                    fflush(csv_app);

                } else {
                    stats.outro_transp++;
                    fprintf(csv_trans, "%s,outro,%s,0,%s,0,%zu\n", ts, src_ip, dst_ip, camada_len);
                    fflush(csv_trans);
                }
            }

        } else if (l2_proto == ETH_P_IPV6) {        // ===== IPv6 =====
            if (frame_len < l2_len + sizeof(struct ip6_hdr)) continue;
            struct ip6_hdr *ip6 = (struct ip6_hdr *)(buffer + l2_len);
            inet_ntop(AF_INET6, &ip6->ip6_src, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET6, &ip6->ip6_dst, dst_ip, sizeof(dst_ip));
            camada_len = ntohs(ip6->ip6_plen) + sizeof(struct ip6_hdr);
            stats.ipv6++;
            fprintf(csv_rede, "%s,IPv6,%s,%s,%d,-,%zu\n", ts, src_ip, dst_ip, ip6->ip6_nxt, camada_len);
            fflush(csv_rede);

        } else {                                    // ===== Outros L3 =====
            stats.outro_rede++;
            fprintf(csv_rede, "%s,outro,-,-,0,-,%zu\n", ts, frame_len);
            fflush(csv_rede);
        }

        time_t now = time(NULL);
        if (now != last_print) { last_print = now; print_stats(); }
    }

    fclose(csv_rede); fclose(csv_trans); fclose(csv_app); close(sock);
    return 0;
}
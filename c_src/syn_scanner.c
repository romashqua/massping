/**
 * SYN Scanner NIF for MassPing
 * 
 * High-performance SYN port scanner.
 * - Linux: Uses raw sockets (fast, no external dependencies)
 * - macOS: Uses libpcap for packet capture (BPF-based)
 * 
 * Requires root/sudo to run.
 * 
 * Benefits over TCP connect():
 * - 3x faster (1 packet vs 3 packets)
 * - Less detectable (half-open scan)
 * - Lower resource usage (no socket state)
 */

#include <erl_nif.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <ifaddrs.h>

#ifdef __APPLE__
/* macOS: Use libpcap for reliable packet capture */
#include <pcap/pcap.h>
#include <net/if.h>
/* Note: pcap/bpf.h is already included by pcap.h, don't include net/bpf.h */
#define USE_PCAP 1
#else
/* Linux: Use raw sockets */
#define USE_PCAP 0
#endif

/* Pseudo header for TCP checksum calculation */
struct pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

/* Result codes */
#define SCAN_OPEN     1
#define SCAN_CLOSED   2
#define SCAN_FILTERED 3
#define SCAN_ERROR    4

/* Global state */
static int raw_send_socket = -1;
static uint32_t local_ip = 0;
static char local_interface[64] = {0};

#if USE_PCAP
static pcap_t *pcap_handle = NULL;
static pthread_mutex_t pcap_mutex = PTHREAD_MUTEX_INITIALIZER;
#else
static int raw_recv_socket = -1;
#endif

/* Calculate checksum for IP/TCP headers */
static uint16_t checksum(uint16_t *ptr, int nbytes) {
    long sum = 0;
    uint16_t oddbyte;
    uint16_t answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((uint8_t *)&oddbyte) = *(uint8_t *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (uint16_t)~sum;

    return answer;
}

/* Get local IP address and interface name */
static uint32_t get_local_ip(void) {
    struct ifaddrs *ifaddr, *ifa;
    uint32_t ip = 0;
    
    if (getifaddrs(&ifaddr) == -1) {
        return inet_addr("127.0.0.1");
    }
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        
        /* Skip loopback */
        if (strcmp(ifa->ifa_name, "lo") == 0 || strcmp(ifa->ifa_name, "lo0") == 0) continue;
        
        struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
        
        /* Skip link-local addresses */
        uint32_t addr = ntohl(sa->sin_addr.s_addr);
        if ((addr & 0xFFFF0000) == 0xA9FE0000) continue;  /* 169.254.x.x */
        
        ip = sa->sin_addr.s_addr;
        strncpy(local_interface, ifa->ifa_name, sizeof(local_interface) - 1);
        
        /* Prefer en0/eth0 (primary interface) */
        if (strncmp(ifa->ifa_name, "en", 2) == 0 || 
            strncmp(ifa->ifa_name, "eth", 3) == 0) {
            break;
        }
    }
    
    freeifaddrs(ifaddr);
    return ip ? ip : inet_addr("127.0.0.1");
}

#if USE_PCAP
/* macOS: Initialize pcap for packet capture */
static int init_pcap(void) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_handle != NULL) {
        return 0;  /* Already initialized */
    }
    
    /* Open pcap on the detected interface */
    pcap_handle = pcap_open_live(local_interface, 65535, 0, 1, errbuf);
    if (pcap_handle == NULL) {
        /* Try default interface */
        pcap_handle = pcap_open_live("en0", 65535, 0, 1, errbuf);
        if (pcap_handle == NULL) {
            return -1;
        }
    }
    
    /* Set non-blocking mode */
    if (pcap_setnonblock(pcap_handle, 1, errbuf) < 0) {
        pcap_close(pcap_handle);
        pcap_handle = NULL;
        return -2;
    }
    
    /* Set BPF filter for TCP SYN-ACK and RST packets */
    struct bpf_program fp;
    char filter[] = "tcp and (tcp[tcpflags] & (tcp-syn|tcp-ack) = (tcp-syn|tcp-ack) or tcp[tcpflags] & tcp-rst != 0)";
    
    if (pcap_compile(pcap_handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        pcap_close(pcap_handle);
        pcap_handle = NULL;
        return -3;
    }
    
    if (pcap_setfilter(pcap_handle, &fp) < 0) {
        pcap_freecode(&fp);
        pcap_close(pcap_handle);
        pcap_handle = NULL;
        return -4;
    }
    
    pcap_freecode(&fp);
    return 0;
}
#endif

/* Initialize raw sockets */
static int init_raw_sockets(void) {
    if (raw_send_socket >= 0) {
        return 0; /* Already initialized */
    }
    
    /* Get local IP first */
    local_ip = get_local_ip();
    
    /* Create raw socket for sending */
#ifdef __APPLE__
    raw_send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
#else
    raw_send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
#endif
    
    if (raw_send_socket < 0) {
        return -1;
    }

#ifndef __APPLE__
    /* Linux: Tell kernel we provide IP header */
    int one = 1;
    if (setsockopt(raw_send_socket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        close(raw_send_socket);
        raw_send_socket = -1;
        return -2;
    }
    
    /* Linux: Create raw socket for receiving */
    raw_recv_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_recv_socket < 0) {
        close(raw_send_socket);
        raw_send_socket = -1;
        return -3;
    }
    
    /* Set non-blocking */
    int flags = fcntl(raw_recv_socket, F_GETFL, 0);
    fcntl(raw_recv_socket, F_SETFL, flags | O_NONBLOCK);
#else
    /* macOS: Initialize pcap for receiving */
    int ret = init_pcap();
    if (ret < 0) {
        close(raw_send_socket);
        raw_send_socket = -1;
        return ret - 10;  /* Offset to distinguish from other errors */
    }
#endif
    
    return 0;
}

/* Build and send SYN packet */
static int send_syn(uint32_t dst_ip, uint16_t dst_port, uint16_t src_port) {
    char packet[sizeof(struct ip) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));
    
    struct ip *iph = (struct ip *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ip));
    
    /* IP Header */
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = htons(sizeof(packet));
    iph->ip_id = htons(rand() & 0xFFFF);
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_sum = 0;
    iph->ip_src.s_addr = local_ip;
    iph->ip_dst.s_addr = dst_ip;
    
    /* TCP Header */
#ifdef __APPLE__
    tcph->th_sport = htons(src_port);
    tcph->th_dport = htons(dst_port);
    tcph->th_seq = htonl(rand());
    tcph->th_ack = 0;
    tcph->th_off = 5;
    tcph->th_flags = TH_SYN;
    tcph->th_win = htons(65535);
    tcph->th_sum = 0;
    tcph->th_urp = 0;
#else
    tcph->source = htons(src_port);
    tcph->dest = htons(dst_port);
    tcph->seq = htonl(rand());
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(65535);
    tcph->check = 0;
    tcph->urg_ptr = 0;
#endif
    
    /* Calculate TCP checksum */
    struct pseudo_header psh;
    psh.src_addr = local_ip;
    psh.dst_addr = dst_ip;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));
    
    char pseudogram[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
    
#ifdef __APPLE__
    tcph->th_sum = checksum((uint16_t *)pseudogram, 
                            sizeof(struct pseudo_header) + sizeof(struct tcphdr));
#else
    tcph->check = checksum((uint16_t *)pseudogram, 
                           sizeof(struct pseudo_header) + sizeof(struct tcphdr));
#endif
    
    /* Send packet */
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = dst_ip;
    dest.sin_port = htons(dst_port);
    
#ifdef __APPLE__
    /* macOS: send only TCP portion, kernel adds IP header */
    if (sendto(raw_send_socket, tcph, sizeof(struct tcphdr), 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        return -1;
    }
#else
    if (sendto(raw_send_socket, packet, sizeof(packet), 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        return -1;
    }
#endif
    
    return 0;
}

#if USE_PCAP
/* macOS: Wait for response using pcap */
static int wait_response_pcap(uint32_t dst_ip, uint16_t dst_port, uint16_t src_port, 
                               int timeout_ms) {
    if (pcap_handle == NULL) return SCAN_FILTERED;
    
    struct timeval start, now;
    gettimeofday(&start, NULL);
    
    while (1) {
        gettimeofday(&now, NULL);
        long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 + 
                          (now.tv_usec - start.tv_usec) / 1000;
        
        if (elapsed_ms >= timeout_ms) break;
        
        pthread_mutex_lock(&pcap_mutex);
        
        struct pcap_pkthdr *header;
        const u_char *packet;
        int ret = pcap_next_ex(pcap_handle, &header, &packet);
        
        pthread_mutex_unlock(&pcap_mutex);
        
        if (ret <= 0) {
            usleep(100);
            continue;
        }
        
        if (header->len < 14 + 20 + 20) continue;
        
        const struct ip *iph = (const struct ip *)(packet + 14);
        if (iph->ip_p != IPPROTO_TCP) continue;
        if (iph->ip_src.s_addr != dst_ip) continue;
        
        const struct tcphdr *tcph = (const struct tcphdr *)(packet + 14 + (iph->ip_hl * 4));
        
        uint16_t sport = ntohs(tcph->th_sport);
        uint16_t dport = ntohs(tcph->th_dport);
        
        if (sport != dst_port || dport != src_port) continue;
        
        if (tcph->th_flags & TH_RST) {
            return SCAN_CLOSED;
        } else if ((tcph->th_flags & TH_SYN) && (tcph->th_flags & TH_ACK)) {
            return SCAN_OPEN;
        }
    }
    
    return SCAN_FILTERED;
}

#else
/* Linux: Wait for response using raw socket */
static int wait_response_raw(uint32_t dst_ip, uint16_t dst_port, uint16_t src_port, 
                              int timeout_ms) {
    struct pollfd pfd;
    pfd.fd = raw_recv_socket;
    pfd.events = POLLIN;
    
    char buffer[65536];
    struct timeval start, now;
    gettimeofday(&start, NULL);
    
    while (1) {
        gettimeofday(&now, NULL);
        long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 + 
                          (now.tv_usec - start.tv_usec) / 1000;
        
        if (elapsed_ms >= timeout_ms) {
            return SCAN_FILTERED;
        }
        
        int remaining = timeout_ms - elapsed_ms;
        int ret = poll(&pfd, 1, remaining);
        
        if (ret <= 0) {
            return SCAN_FILTERED;
        }
        
        ssize_t len = recv(raw_recv_socket, buffer, sizeof(buffer), 0);
        if (len < 0) continue;
        
        struct ip *iph = (struct ip *)buffer;
        if (iph->ip_p != IPPROTO_TCP) continue;
        if (iph->ip_src.s_addr != dst_ip) continue;
        
        struct tcphdr *tcph = (struct tcphdr *)(buffer + (iph->ip_hl * 4));
        
        uint16_t sport = ntohs(tcph->source);
        uint16_t dport = ntohs(tcph->dest);
        
        if (sport != dst_port || dport != src_port) continue;
        
        if (tcph->rst) {
            return SCAN_CLOSED;
        }
        if (tcph->syn && tcph->ack) {
            return SCAN_OPEN;
        }
    }
}
#endif

/* Platform-independent wait for response */
static int wait_response(uint32_t dst_ip, uint16_t dst_port, uint16_t src_port, 
                         int timeout_ms) {
#if USE_PCAP
    return wait_response_pcap(dst_ip, dst_port, src_port, timeout_ms);
#else
    return wait_response_raw(dst_ip, dst_port, src_port, timeout_ms);
#endif
}

/* NIF: Initialize scanner */
static ERL_NIF_TERM syn_init(ErlNifEnv *env, int argc, 
                             const ERL_NIF_TERM argv[]) {
    int ret = init_raw_sockets();
    
    if (ret < 0) {
        return enif_make_tuple2(env,
            enif_make_atom(env, "error"),
            enif_make_tuple2(env,
                enif_make_atom(env, "init_failed"),
                enif_make_int(env, ret)));
    }
    
    /* Return local IP and interface for logging */
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = local_ip;
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
    
    char info[128];
    snprintf(info, sizeof(info), "%s (%s)", ip_str, local_interface);
    
    return enif_make_tuple2(env,
        enif_make_atom(env, "ok"),
        enif_make_string(env, info, ERL_NIF_LATIN1));
}

/* NIF: Check if we have root privileges */
static ERL_NIF_TERM nif_is_root(ErlNifEnv *env, int argc,
                                const ERL_NIF_TERM argv[]) {
    if (geteuid() == 0) {
        return enif_make_atom(env, "true");
    }
    return enif_make_atom(env, "false");
}

/* NIF: Get platform info */
static ERL_NIF_TERM nif_platform(ErlNifEnv *env, int argc,
                                  const ERL_NIF_TERM argv[]) {
#if USE_PCAP
    return enif_make_tuple2(env,
        enif_make_atom(env, "macos"),
        enif_make_atom(env, "pcap"));
#else
    return enif_make_tuple2(env,
        enif_make_atom(env, "linux"),
        enif_make_atom(env, "raw_socket"));
#endif
}

/* NIF: Single SYN scan */
static ERL_NIF_TERM nif_syn_scan(ErlNifEnv *env, int argc,
                                  const ERL_NIF_TERM argv[]) {
    if (argc != 3) {
        return enif_make_badarg(env);
    }
    
    /* Parse IP tuple {A,B,C,D} */
    int arity;
    const ERL_NIF_TERM *ip_tuple;
    if (!enif_get_tuple(env, argv[0], &arity, &ip_tuple) || arity != 4) {
        return enif_make_badarg(env);
    }
    
    unsigned int a, b, c, d;
    if (!enif_get_uint(env, ip_tuple[0], &a) ||
        !enif_get_uint(env, ip_tuple[1], &b) ||
        !enif_get_uint(env, ip_tuple[2], &c) ||
        !enif_get_uint(env, ip_tuple[3], &d)) {
        return enif_make_badarg(env);
    }
    
    /* Parse port */
    unsigned int port;
    if (!enif_get_uint(env, argv[1], &port) || port > 65535) {
        return enif_make_badarg(env);
    }
    
    /* Parse timeout */
    unsigned int timeout_ms;
    if (!enif_get_uint(env, argv[2], &timeout_ms)) {
        return enif_make_badarg(env);
    }
    
    /* Build destination IP */
    uint32_t dst_ip = htonl((a << 24) | (b << 16) | (c << 8) | d);
    
    /* Generate random source port */
    uint16_t src_port = 40000 + (rand() % 20000);
    
    /* Send SYN */
    if (send_syn(dst_ip, (uint16_t)port, src_port) < 0) {
        return enif_make_tuple2(env,
            enif_make_atom(env, "error"),
            enif_make_atom(env, "send_failed"));
    }
    
    /* Wait for response */
    int result = wait_response(dst_ip, (uint16_t)port, src_port, timeout_ms);
    
    ERL_NIF_TERM result_atom;
    switch (result) {
        case SCAN_OPEN:
            result_atom = enif_make_atom(env, "open");
            break;
        case SCAN_CLOSED:
            result_atom = enif_make_atom(env, "closed");
            break;
        case SCAN_FILTERED:
            result_atom = enif_make_atom(env, "filtered");
            break;
        default:
            result_atom = enif_make_atom(env, "error");
    }
    
    return enif_make_tuple2(env, result_atom, enif_make_uint(env, port));
}

/* NIF: Batch SYN scan (send all, then receive) - more efficient */
static ERL_NIF_TERM nif_syn_scan_batch(ErlNifEnv *env, int argc,
                                        const ERL_NIF_TERM argv[]) {
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    
    unsigned int timeout_ms;
    if (!enif_get_uint(env, argv[1], &timeout_ms)) {
        return enif_make_badarg(env);
    }
    
    unsigned int list_len;
    if (!enif_get_list_length(env, argv[0], &list_len)) {
        return enif_make_badarg(env);
    }
    
    if (list_len == 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "ok"), 
                               enif_make_list(env, 0));
    }
    
    /* Allocate arrays for tracking */
    typedef struct {
        uint32_t ip;
        uint16_t port;
        uint16_t src_port;
        int result;
    } target_t;
    
    target_t *targets = enif_alloc(sizeof(target_t) * list_len);
    if (!targets) {
        return enif_make_tuple2(env,
            enif_make_atom(env, "error"),
            enif_make_atom(env, "alloc_failed"));
    }
    
    /* Parse list and send SYNs */
    ERL_NIF_TERM list = argv[0];
    ERL_NIF_TERM head, tail;
    unsigned int idx = 0;
    
    while (enif_get_list_cell(env, list, &head, &tail)) {
        int arity;
        const ERL_NIF_TERM *tuple;
        
        if (!enif_get_tuple(env, head, &arity, &tuple) || arity != 2) {
            enif_free(targets);
            return enif_make_badarg(env);
        }
        
        const ERL_NIF_TERM *ip_tuple;
        int ip_arity;
        if (!enif_get_tuple(env, tuple[0], &ip_arity, &ip_tuple) || ip_arity != 4) {
            enif_free(targets);
            return enif_make_badarg(env);
        }
        
        unsigned int a, b, c, d, port;
        enif_get_uint(env, ip_tuple[0], &a);
        enif_get_uint(env, ip_tuple[1], &b);
        enif_get_uint(env, ip_tuple[2], &c);
        enif_get_uint(env, ip_tuple[3], &d);
        enif_get_uint(env, tuple[1], &port);
        
        targets[idx].ip = htonl((a << 24) | (b << 16) | (c << 8) | d);
        targets[idx].port = (uint16_t)port;
        targets[idx].src_port = 40000 + (rand() % 20000);
        targets[idx].result = SCAN_FILTERED;
        
        /* Send SYN */
        send_syn(targets[idx].ip, targets[idx].port, targets[idx].src_port);
        
        idx++;
        list = tail;
    }
    
    /* Wait for responses */
    struct timeval start, now;
    gettimeofday(&start, NULL);
    
    unsigned int responses = 0;
    
#if USE_PCAP
    /* macOS: Use pcap for capturing responses */
    while (responses < list_len) {
        gettimeofday(&now, NULL);
        long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 + 
                          (now.tv_usec - start.tv_usec) / 1000;
        
        if (elapsed_ms >= (long)timeout_ms) break;
        
        pthread_mutex_lock(&pcap_mutex);
        
        struct pcap_pkthdr *header;
        const u_char *packet;
        int ret = pcap_next_ex(pcap_handle, &header, &packet);
        
        pthread_mutex_unlock(&pcap_mutex);
        
        if (ret <= 0) {
            usleep(100);
            continue;
        }
        
        if (header->len < 14 + 20 + 20) continue;
        
        const struct ip *iph = (const struct ip *)(packet + 14);
        if (iph->ip_p != IPPROTO_TCP) continue;
        
        const struct tcphdr *tcph = (const struct tcphdr *)(packet + 14 + (iph->ip_hl * 4));
        uint16_t sport = ntohs(tcph->th_sport);
        uint16_t dport = ntohs(tcph->th_dport);
        
        for (unsigned int i = 0; i < list_len; i++) {
            if (targets[i].result != SCAN_FILTERED) continue;
            if (iph->ip_src.s_addr != targets[i].ip) continue;
            if (sport != targets[i].port) continue;
            if (dport != targets[i].src_port) continue;
            
            if (tcph->th_flags & TH_RST) {
                targets[i].result = SCAN_CLOSED;
            } else if ((tcph->th_flags & TH_SYN) && (tcph->th_flags & TH_ACK)) {
                targets[i].result = SCAN_OPEN;
            }
            responses++;
            break;
        }
    }
#else
    /* Linux: Use raw socket */
    struct pollfd pfd;
    pfd.fd = raw_recv_socket;
    pfd.events = POLLIN;
    
    char buffer[65536];
    
    while (responses < list_len) {
        gettimeofday(&now, NULL);
        long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 + 
                          (now.tv_usec - start.tv_usec) / 1000;
        
        if (elapsed_ms >= (long)timeout_ms) break;
        
        int remaining = timeout_ms - elapsed_ms;
        int ret = poll(&pfd, 1, remaining > 10 ? 10 : remaining);
        
        if (ret <= 0) continue;
        
        ssize_t len = recv(raw_recv_socket, buffer, sizeof(buffer), 0);
        if (len < 0) continue;
        
        struct ip *iph = (struct ip *)buffer;
        if (iph->ip_p != IPPROTO_TCP) continue;
        
        struct tcphdr *tcph = (struct tcphdr *)(buffer + (iph->ip_hl * 4));
        uint16_t sport = ntohs(tcph->source);
        uint16_t dport = ntohs(tcph->dest);
        
        for (unsigned int i = 0; i < list_len; i++) {
            if (targets[i].result != SCAN_FILTERED) continue;
            if (iph->ip_src.s_addr != targets[i].ip) continue;
            if (sport != targets[i].port) continue;
            if (dport != targets[i].src_port) continue;
            
            if (tcph->rst) {
                targets[i].result = SCAN_CLOSED;
            } else if (tcph->syn && tcph->ack) {
                targets[i].result = SCAN_OPEN;
            }
            responses++;
            break;
        }
    }
#endif
    
    /* Build results list */
    ERL_NIF_TERM results = enif_make_list(env, 0);
    
    for (int i = list_len - 1; i >= 0; i--) {
        ERL_NIF_TERM result_atom;
        switch (targets[i].result) {
            case SCAN_OPEN: result_atom = enif_make_atom(env, "open"); break;
            case SCAN_CLOSED: result_atom = enif_make_atom(env, "closed"); break;
            default: result_atom = enif_make_atom(env, "filtered");
        }
        
        uint32_t ip = ntohl(targets[i].ip);
        ERL_NIF_TERM ip_term = enif_make_tuple4(env,
            enif_make_uint(env, (ip >> 24) & 0xFF),
            enif_make_uint(env, (ip >> 16) & 0xFF),
            enif_make_uint(env, (ip >> 8) & 0xFF),
            enif_make_uint(env, ip & 0xFF));
        
        ERL_NIF_TERM entry = enif_make_tuple3(env,
            ip_term,
            enif_make_tuple2(env, result_atom, enif_make_uint(env, targets[i].port)),
            enif_make_uint(env, targets[i].port));
        
        results = enif_make_list_cell(env, entry, results);
    }
    
    enif_free(targets);
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), results);
}

/* NIF: Cleanup */
static ERL_NIF_TERM nif_cleanup(ErlNifEnv *env, int argc,
                                const ERL_NIF_TERM argv[]) {
    if (raw_send_socket >= 0) {
        close(raw_send_socket);
        raw_send_socket = -1;
    }
    
#if USE_PCAP
    if (pcap_handle != NULL) {
        pcap_close(pcap_handle);
        pcap_handle = NULL;
    }
#else
    if (raw_recv_socket >= 0) {
        close(raw_recv_socket);
        raw_recv_socket = -1;
    }
#endif
    
    return enif_make_atom(env, "ok");
}

/* NIF function table */
static ErlNifFunc nif_funcs[] = {
    {"init", 0, syn_init, 0},
    {"is_root", 0, nif_is_root, 0},
    {"platform", 0, nif_platform, 0},
    {"syn_scan", 3, nif_syn_scan, 0},
    {"syn_scan_batch", 2, nif_syn_scan_batch, 0},
    {"cleanup", 0, nif_cleanup, 0}
};

/* Load/Unload callbacks */
static int load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info) {
    srand(time(NULL) ^ getpid());
    return 0;
}

static void unload(ErlNifEnv *env, void *priv_data) {
    if (raw_send_socket >= 0) close(raw_send_socket);
#if USE_PCAP
    if (pcap_handle != NULL) pcap_close(pcap_handle);
#else
    if (raw_recv_socket >= 0) close(raw_recv_socket);
#endif
}

ERL_NIF_INIT(syn_scanner, nif_funcs, load, NULL, NULL, unload)

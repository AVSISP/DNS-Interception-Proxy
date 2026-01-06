#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <time.h>

#define BUFFER_SIZE 4096
#define DNS_SERVER "1.1.1.1"
#define DNS_PORT 53
#define THREAD_POOL_SIZE 20
#define MAX_PENDING 1000
#define DNS_TIMEOUT_MS 300

typedef struct {
    int is_ipv6;
    union {
        uint32_t ipv4;
        struct in6_addr ipv6;
    } client_ip;
    union {
        uint32_t ipv4;
        struct in6_addr ipv6;
    } original_dest;
    uint16_t client_port;
    unsigned char dns_query[BUFFER_SIZE];
    int query_len;
    int sock;
    time_t start_time;
} pending_query_t;

struct nfq_handle *h;
struct nfq_q_handle *qh;
int fd;

pending_query_t *pending_queries[MAX_PENDING];
pthread_mutex_t pending_mutex = PTHREAD_MUTEX_INITIALIZER;

int epoll_fd;
int query_count = 0;
int dropped_count = 0;

int send_spoofed_response_ipv4(uint32_t client_ip, uint16_t client_port,
                                 uint32_t spoof_from_ip,
                                 unsigned char *dns_response, int response_len)
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        return -1;
    }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        close(sock);
        return -1;
    }

    struct iphdr ip_hdr;
    memset(&ip_hdr, 0, sizeof(ip_hdr));
    ip_hdr.version = 4;
    ip_hdr.ihl = 5;
    ip_hdr.ttl = 64;
    ip_hdr.protocol = IPPROTO_UDP;
    ip_hdr.saddr = spoof_from_ip;
    ip_hdr.daddr = client_ip;
    ip_hdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + response_len);
    ip_hdr.id = htons(12345);
    ip_hdr.check = 0;

    struct udphdr udp_hdr;
    memset(&udp_hdr, 0, sizeof(udp_hdr));
    udp_hdr.source = htons(DNS_PORT);
    udp_hdr.dest = client_port;
    udp_hdr.len = htons(sizeof(struct udphdr) + response_len);
    udp_hdr.check = 0;

    unsigned char packet[BUFFER_SIZE];
    memcpy(packet, &ip_hdr, sizeof(struct iphdr));
    memcpy(packet + sizeof(struct iphdr), &udp_hdr, sizeof(struct udphdr));
    memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr),
           dns_response, response_len);

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = client_ip;
    dest_addr.sin_port = client_port;

    int total_len = sizeof(struct iphdr) + sizeof(struct udphdr) + response_len;
    sendto(sock, packet, total_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    close(sock);
    return 0;
}

int send_spoofed_response_ipv6(struct in6_addr *client_ip, uint16_t client_port,
                                 struct in6_addr *spoof_from_ip,
                                 unsigned char *dns_response, int response_len)
{
    int sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("IPv6 socket");
        return -1;
    }

    // Enable transparent source address
    int on = 1;
    if (setsockopt(sock, SOL_IPV6, IPV6_TRANSPARENT, &on, sizeof(on)) < 0) {
        // Ignore error if not available - try without it
    }

    // Bind to spoofed source address
    struct sockaddr_in6 bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin6_family = AF_INET6;
    memcpy(&bind_addr.sin6_addr, spoof_from_ip, sizeof(struct in6_addr));
    bind_addr.sin6_port = htons(DNS_PORT);

    if (bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("IPv6 bind");
        close(sock);
        return -1;
    }

    struct sockaddr_in6 dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin6_family = AF_INET6;
    memcpy(&dest_addr.sin6_addr, client_ip, sizeof(struct in6_addr));
    dest_addr.sin6_port = client_port;

    int sent = sendto(sock, dns_response, response_len, 0, 
                      (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    if (sent < 0) {
        perror("IPv6 sendto");
    }

    close(sock);
    return sent >= 0 ? 0 : -1;
}

void cleanup_query(pending_query_t *query)
{
    if (query->sock >= 0) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, query->sock, NULL);
        close(query->sock);
    }

    pthread_mutex_lock(&pending_mutex);
    for (int i = 0; i < MAX_PENDING; i++) {
        if (pending_queries[i] == query) {
            pending_queries[i] = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&pending_mutex);
    free(query);
}

void *event_loop_thread(void *arg)
{
    struct epoll_event events[100];
    printf("[*] Event loop thread started\n");

    while (1) {
        int nfds = epoll_wait(epoll_fd, events, 100, 100);

        for (int i = 0; i < nfds; i++) {
            pending_query_t *query = (pending_query_t *)events[i].data.ptr;

            if (events[i].events & EPOLLIN) {
                unsigned char response[BUFFER_SIZE];
                struct sockaddr_in src_addr;
                socklen_t src_len = sizeof(src_addr);

                int recv_len = recvfrom(query->sock, response, BUFFER_SIZE, 0,
                                         (struct sockaddr *)&src_addr, &src_len);

                if (recv_len > 0) {
                    if (query->is_ipv6) {
                        send_spoofed_response_ipv6(&query->client_ip.ipv6, query->client_port,
                                                    &query->original_dest.ipv6, response, recv_len);
                    } else {
                        send_spoofed_response_ipv4(query->client_ip.ipv4, query->client_port,
                                                    query->original_dest.ipv4, response, recv_len);
                    }
                }

                cleanup_query(query);
            }
        }

        // Timeout check
        time_t now = time(NULL);
        pthread_mutex_lock(&pending_mutex);
        for (int i = 0; i < MAX_PENDING; i++) {
            if (pending_queries[i] &&
                (now - pending_queries[i]->start_time) > 1) {
                pending_query_t *query = pending_queries[i];
                pending_queries[i] = NULL;
                pthread_mutex_unlock(&pending_mutex);
                close(query->sock);
                free(query);
                pthread_mutex_lock(&pending_mutex);
            }
        }
        pthread_mutex_unlock(&pending_mutex);
    }

    return NULL;
}

int add_pending_query(pending_query_t *query)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        free(query);
        return -1;
    }

    // Set non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    query->sock = sock;
    query->start_time = time(NULL);

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(DNS_PORT);
    dest_addr.sin_addr.s_addr = inet_addr(DNS_SERVER);

    sendto(sock, query->dns_query, query->query_len, 0,
           (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = query;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev) < 0) {
        close(sock);
        free(query);
        return -1;
    }

    pthread_mutex_lock(&pending_mutex);
    int added = 0;
    for (int i = 0; i < MAX_PENDING; i++) {
        if (pending_queries[i] == NULL) {
            pending_queries[i] = query;
            added = 1;
            query_count++;
            break;
        }
    }
    pthread_mutex_unlock(&pending_mutex);

    if (!added) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, sock, NULL);
        close(sock);
        free(query);
        dropped_count++;
        if (dropped_count % 100 == 0) {
            printf("[!] DROPPED %d queries (too many pending)\n", dropped_count);
        }
        return -1;
    }

    return 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfad, void *data)
{
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
    uint32_t id = ntohl(ph->packet_id);

    unsigned char *full_packet;
    int pkt_len = nfq_get_payload(nfad, &full_packet);

    // Return verdict IMMEDIATELY
    nfq_set_verdict(qh, id, NF_DROP, 0, NULL);

    if (pkt_len < 1) {
        return 0;
    }

    pending_query_t *query = malloc(sizeof(pending_query_t));
    if (!query) {
        return 0;
    }

    // Determine IP version
    unsigned char version = (full_packet[0] >> 4) & 0x0F;

    if (version == 4 && pkt_len >= (int)(sizeof(struct iphdr) + sizeof(struct udphdr))) {
        struct iphdr *ip_hdr = (struct iphdr *)full_packet;
        struct udphdr *udp_hdr = (struct udphdr *)(full_packet + ip_hdr->ihl * 4);
        unsigned char *payload = full_packet + ip_hdr->ihl * 4 + sizeof(struct udphdr);
        int payload_len = pkt_len - ip_hdr->ihl * 4 - sizeof(struct udphdr);

        query->is_ipv6 = 0;
        query->client_ip.ipv4 = ip_hdr->saddr;
        query->original_dest.ipv4 = ip_hdr->daddr;
        query->client_port = udp_hdr->source;
        query->query_len = payload_len;
        memcpy(query->dns_query, payload, payload_len);

        add_pending_query(query);
    } 
    else if (version == 6 && pkt_len >= (int)(sizeof(struct ip6_hdr) + sizeof(struct udphdr))) {
        struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)full_packet;
        struct udphdr *udp_hdr = (struct udphdr *)(full_packet + sizeof(struct ip6_hdr));
        unsigned char *payload = full_packet + sizeof(struct ip6_hdr) + sizeof(struct udphdr);
        int payload_len = pkt_len - sizeof(struct ip6_hdr) - sizeof(struct udphdr);

        query->is_ipv6 = 1;
        memcpy(&query->client_ip.ipv6, &ip6_hdr->ip6_src, sizeof(struct in6_addr));
        memcpy(&query->original_dest.ipv6, &ip6_hdr->ip6_dst, sizeof(struct in6_addr));
        query->client_port = udp_hdr->source;
        query->query_len = payload_len;
        memcpy(query->dns_query, payload, payload_len);

        add_pending_query(query);
    }
    else {
        free(query);
    }

    return 0;
}

int main()
{
    printf("[*] DNS Proxy starting (Async/Epoll + IPv4/IPv6)...\n");
    printf("[*] Max pending queries: %d\n", MAX_PENDING);
    printf("[*] Query timeout: 1 second\n");
    printf("[*] Forwarding to: %s:%d (IPv4 backend)\n\n", DNS_SERVER, DNS_PORT);

    memset(pending_queries, 0, sizeof(pending_queries));

    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1");
        exit(1);
    }

    pthread_t event_thread;
    pthread_create(&event_thread, NULL, event_loop_thread, NULL);

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    nfq_unbind_pf(h, PF_INET);
    nfq_unbind_pf(h, PF_INET6);

    if (nfq_bind_pf(h, PF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf(PF_INET)\n");
        exit(1);
    }

    if (nfq_bind_pf(h, PF_INET6) < 0) {
        fprintf(stderr, "error during nfq_bind_pf(PF_INET6)\n");
        exit(1);
    }

    qh = nfq_create_queue(h, 53, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "error during nfq_set_mode()\n");
        exit(1);
    }

    fd = nfq_fd(h);

    unsigned char buf[4096];
    int rv;

    printf("[+] DNS proxy ready (accepting IPv4 and IPv6)\n\n");

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, (char *)buf, rv);
    }

    printf("\n[*] Shutting down...\n");
    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}

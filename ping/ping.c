#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <poll.h>
#include <signal.h>
#include <math.h>

#define TIMEOUT 10 // Timeout in seconds
#define BUFFER_SIZE 1024

int packets_sent = 0;
int packets_received = 0;
double total_rtt = 0;
double min_rtt = 1000000;
double max_rtt = 0;
char *address = NULL; // Store the address globally

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

unsigned short icmp6_checksum(struct in6_addr *src, struct in6_addr *dst, void *icmp6_hdr, int len) {
    struct {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t len;
        uint8_t zero[3];
        uint8_t next_hdr;
    } pseudo_header;

    memset(&pseudo_header, 0, sizeof(pseudo_header));
    pseudo_header.src = *src;
    pseudo_header.dst = *dst;
    pseudo_header.len = htonl(len);
    pseudo_header.next_hdr = IPPROTO_ICMPV6;

    unsigned int sum = checksum(&pseudo_header, sizeof(pseudo_header));
    sum += checksum(icmp6_hdr, len);

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

void print_statistics(const char *address) {
    printf("\n--- %s ping statistics ---\n", address);
    printf("%d packets transmitted, %d received, time %.3fms\n",
           packets_sent, packets_received, total_rtt);

    if (packets_received > 0) {
        double avg_rtt = total_rtt / packets_received;
        double mdev = sqrt(((max_rtt - avg_rtt) * (max_rtt - avg_rtt)) / packets_received);
        printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3fms\n",
               min_rtt, avg_rtt, max_rtt, mdev);
    }
    exit(0);
}

void handle_signal(int sig) {
    if (sig == SIGINT) {
        print_statistics(address);
    }
}

void send_ping(int sock, struct sockaddr *addr, socklen_t addrlen, int type, int seq_num, struct in6_addr *src, struct in6_addr *dst) {
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);

    if (type == 4) { // IPv4
        struct icmphdr *icmp_hdr = (struct icmphdr *)buffer;
        icmp_hdr->type = ICMP_ECHO;
        icmp_hdr->code = 0;
        icmp_hdr->checksum = 0;
        icmp_hdr->un.echo.id = getpid();
        icmp_hdr->un.echo.sequence = seq_num;
        icmp_hdr->checksum = checksum(buffer, sizeof(struct icmphdr));
    } else if (type == 6) { // IPv6
        struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)buffer;
        icmp6_hdr->icmp6_type = ICMP6_ECHO_REQUEST;
        icmp6_hdr->icmp6_code = 0;
        icmp6_hdr->icmp6_id = getpid();
        icmp6_hdr->icmp6_seq = seq_num;
        icmp6_hdr->icmp6_cksum = icmp6_checksum(src, dst, icmp6_hdr, sizeof(struct icmp6_hdr));
    }

    if (sendto(sock, buffer, sizeof(struct icmp6_hdr), 0, addr, addrlen) <= 0) {
        perror("sendto");
    } else {
        packets_sent++;
    }
}

void receive_ping(int sock, struct timeval *start_time, int seq_num, const char *address, int type) {
    char buffer[BUFFER_SIZE];
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    struct timeval end_time;

    if (recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&addr, &addrlen) <= 0) {
        perror("recvfrom");
        return;
    }

    gettimeofday(&end_time, NULL);

    double rtt = (end_time.tv_sec - start_time->tv_sec) * 1000.0;
    rtt += (end_time.tv_usec - start_time->tv_usec) / 1000.0;

    packets_received++;
    total_rtt += rtt;
    if (rtt < min_rtt)
        min_rtt = rtt;
    if (rtt > max_rtt)
        max_rtt = rtt;

    int ttl = 0;
    if (type == 4) { // IPv4
        struct iphdr *ip_hdr = (struct iphdr *)buffer;
        ttl = ip_hdr->ttl;
        printf("64 bytes from %s: icmp_seq=%d ttl=%d time=%.3fms\n",
               address, seq_num, ttl, rtt);
    } else if (type == 6) { // IPv6
        struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)buffer;
        ttl = ip6_hdr->ip6_hlim; // Hop limit for IPv6
        printf("64 bytes from %s: icmp_seq=%d hop_limit=%d time=%.3fms\n",
               address, seq_num, ttl, rtt);
    }
}

int main(int argc, char *argv[]) {
    int opt;
    int type = 0;
    int count = -1;
    int flood = 0;

    while ((opt = getopt(argc, argv, "a:t:c:f")) != -1) {
        switch (opt) {
        case 'a':
            address = optarg;
            break;
        case 't':
            type = atoi(optarg);
            break;
        case 'c':
            count = atoi(optarg);
            break;
        case 'f':
            flood = 1;
            break;
        default:
            fprintf(stderr, "Usage: %s -a <address> -t <4|6> [-c count] [-f]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (!address || (type != 4 && type != 6)) {
        fprintf(stderr, "Usage: %s -a <address> -t <4|6> [-c count] [-f]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int sock;
    struct in6_addr src, dst;

    if (type == 4) {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) {
            perror("socket");
            exit(EXIT_FAILURE);
        }
    } else {
        sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (sock < 0) {
            perror("socket");
            exit(EXIT_FAILURE);
        }

        struct sockaddr_in6 dest6;
        memset(&dest6, 0, sizeof(dest6));
        dest6.sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, address, &dest6.sin6_addr) <= 0) {
            perror("inet_pton");
            exit(EXIT_FAILURE);
        }

        src = in6addr_any;
        dst = dest6.sin6_addr;
    }

    signal(SIGINT, handle_signal);

    struct timeval start_time;
    printf("Pinging %s with 64 bytes of data:\n", address);
    for (int i = 0; count == -1 || i < count; i++) {
        gettimeofday(&start_time, NULL);
        send_ping(sock, (struct sockaddr *)&dst, sizeof(struct sockaddr_in6), type, i, &src, &dst);

        struct pollfd pfd = {.fd = sock, .events = POLLIN};
        int ret = poll(&pfd, 1, TIMEOUT * 1000);

        if (ret > 0) {
            receive_ping(sock, &start_time, i + 1, address, type);
        } else if (ret == 0) {
            printf("Request timeout for seq=%d\n", i + 1);
        } else {
            perror("poll");
            break;
        }

        if (!flood) {
            sleep(1);
        }
    }

    print_statistics(address);
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <poll.h>
#include "traceroute.h"

#define MAX_HOPS 30
#define PROBES_PER_HOP 3
#define TIMEOUT 1 // 1 second timeout
#define BUFFER_SIZE 1024

unsigned short checksum(void *b, int len)
{
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
    {
        sum += *buf++;
    }
    if (len == 1)
    {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void send_probe(int sock, struct sockaddr *dest, int ttl, int seq_num)
{
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);

    struct icmphdr *icmp_hdr = (struct icmphdr *)buffer;
    icmp_hdr->type = ICMP_ECHO;
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    icmp_hdr->un.echo.id = getpid();
    icmp_hdr->un.echo.sequence = seq_num;
    icmp_hdr->checksum = checksum(buffer, sizeof(struct icmphdr));

    if (sendto(sock, buffer, sizeof(struct icmphdr), 0, dest, sizeof(struct sockaddr_in)) < 0)
    {
        perror("sendto");
    }
}

int receive_probe(int sock, struct sockaddr_in *recv_addr, double *rtt)
{
    char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(*recv_addr);
    struct timeval start, end;

    gettimeofday(&start, NULL);

    struct pollfd pfd = {.fd = sock, .events = POLLIN};
    int ret = poll(&pfd, 1, TIMEOUT * 1000);

    if (ret > 0)
    {
        if (recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)recv_addr, &addr_len) > 0)
        {
            gettimeofday(&end, NULL);
            *rtt = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
            return 1; // Success
        }
    }

    return 0; // Timeout or error
}

int main(int argc, char *argv[])
{
    if (argc != 3 || strcmp(argv[1], "-a") != 0)
    {
        fprintf(stderr, "Usage: %s -a <address>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *target_ip = argv[2];
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;

    if (inet_pton(AF_INET, target_ip, &dest.sin_addr) <= 0)
    {
        perror("inet_pton");
        exit(EXIT_FAILURE);
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    printf("traceroute to %s, %d hops max\n", target_ip, MAX_HOPS);

    for (int ttl = 1; ttl <= MAX_HOPS; ttl++)
    {
        setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

        struct sockaddr_in recv_addr;
        int responses = 0;
        double total_rtt = 0.0;

        printf("%2d ", ttl);

        for (int probe = 0; probe < PROBES_PER_HOP; probe++)
        {
            send_probe(sock, (struct sockaddr *)&dest, ttl, probe + 1);

            double rtt = 0.0;
            int result = receive_probe(sock, &recv_addr, &rtt);

            if (result == 1)
            { // Received a response
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &recv_addr.sin_addr, ip_str, sizeof(ip_str));
                if (probe == 0)
                    printf("%s ", ip_str);
                printf("%.3fms ", rtt);
                total_rtt += rtt;
                responses++;
            }
            else
            {
                printf("* ");
            }
        }

        printf("\n");

        if (responses > 0 && recv_addr.sin_addr.s_addr == dest.sin_addr.s_addr)
        {
            printf("Reached destination\n");
            break;
        }

        if (ttl == MAX_HOPS)
        {
            printf("Destination unreachable\n");
        }
    }

    close(sock);
    return 0;
}
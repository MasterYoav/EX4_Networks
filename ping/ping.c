#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <poll.h>
#include <signal.h>
#include <math.h>
#include "ping.h"

#define TIMEOUT 10 // Timeout for receiving a response in seconds
#define BUFFER_SIZE 1024 // Buffer size for packets

// Global variables for tracking ping statistics
int packets_sent = 0;
int packets_received = 0;
double total_rtt = 0; 
double min_rtt = 1000000; 
double max_rtt = 0; 
char *address = NULL; // Target address

// Function to print final ping statistics
void print_statistics(const char *address)
{
    printf("\n--- %s ping statistics ---\n", address);
    printf("%d packets transmitted, %d received, time %.3fms\n",
           packets_sent, packets_received, total_rtt);

    if (packets_received > 0)
    {
        // Calculate average RTT
        double avg_rtt = total_rtt / packets_received;

        // Calculate mean deviation (mdev)
        double mdev = 0.0;
        mdev = sqrt(((max_rtt - avg_rtt) * (max_rtt - avg_rtt)) / packets_received);

        // Print RTT statistics
        printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3fms\n",
               min_rtt, avg_rtt, max_rtt, mdev);
    }
    exit(0);
}

// Signal handler for clean termination
void handle_signal(int sig)
{
    if (sig == SIGINT)
    {
        print_statistics(address); // Print statistics before exiting
    }
}

// Function to calculate the ICMP checksum
unsigned short checksum(void *b, int len)
{
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

// Function to send a single ICMP Echo Request packet
void send_ping(int sock, struct sockaddr *addr, socklen_t addrlen, int type, int seq_num)
{
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);

    if (type == 4) // IPv4 packet
    {
        struct icmphdr *icmp_hdr = (struct icmphdr *)buffer;
        icmp_hdr->type = ICMP_ECHO; // Set ICMP type to Echo Request
        icmp_hdr->code = 0;
        icmp_hdr->checksum = 0;
        icmp_hdr->un.echo.id = getpid(); // Unique identifier for this process
        icmp_hdr->un.echo.sequence = seq_num; // Sequence number
        icmp_hdr->checksum = checksum(buffer, sizeof(struct icmphdr)); // Calculate checksum
    }
    else if (type == 6) // IPv6 packet
    {
        struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)buffer;
        icmp6_hdr->icmp6_type = ICMP6_ECHO_REQUEST; // Set ICMPv6 type
        icmp6_hdr->icmp6_code = 0;
        icmp6_hdr->icmp6_id = getpid();
        icmp6_hdr->icmp6_seq = seq_num;
    }

    // Send the packet
    if (sendto(sock, buffer, sizeof(struct icmphdr), 0, addr, addrlen) <= 0)
    {
        perror("sendto");
    }
    else
    {
        packets_sent++; // Increment the sent packet counter
    }
}

// Function to receive and process an ICMP reply
void receive_ping(int sock, struct timeval *start_time, int seq_num, const char *address)
{
    char buffer[BUFFER_SIZE];
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    struct timeval end_time;

    // Receive the ICMP reply
    if (recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&addr, &addrlen) <= 0)
    {
        perror("recvfrom");
        return;
    }

    // Calculate RTT
    gettimeofday(&end_time, NULL);
    double rtt = (end_time.tv_sec - start_time->tv_sec) * 1000.0;
    rtt += (end_time.tv_usec - start_time->tv_usec) / 1000.0;

    packets_received++; // Increment the received packet counter
    total_rtt += rtt; // Add RTT to total
    if (rtt < min_rtt)
        min_rtt = rtt; // Update minimum RTT
    if (rtt > max_rtt)
        max_rtt = rtt; // Update maximum RTT

    // Extract TTL from the IP header (for IPv4)
    int ttl = 0;
    struct iphdr *ip_hdr = (struct iphdr *)buffer;
    if (ip_hdr->version == 4)
    {
        ttl = ip_hdr->ttl;
    }

    // Print the reply information
    printf("64 bytes from %s: icmp_seq=%d ttl=%d time=%.3fms\n",
           address, seq_num, ttl, rtt);
}

int main(int argc, char *argv[])
{
    // Command-line arguments
    int opt;
    int type = 0; // 4 for IPv4, 6 for IPv6
    int count = -1; // Number of packets to send (-1 for infinite)
    int flood = 0; // Whether to send packets continuously without delay

    while ((opt = getopt(argc, argv, "a:t:c:f")) != -1)
    {
        switch (opt)
        {
        case 'a':
            address = optarg; // Target address
            break;
        case 't':
            type = atoi(optarg); // IPv4 or IPv6
            break;
        case 'c':
            count = atoi(optarg); // Number of packets to send
            break;
        case 'f':
            flood = 1; // Enable flood mode
            break;
        default:
            fprintf(stderr, "Usage: %s -a <address> -t <4|6> [-c count] [-f]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    // Validate arguments
    if (!address || (type != 4 && type != 6))
    {
        fprintf(stderr, "Usage: %s -a <address> -t <4|6> [-c count] [-f]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Create raw socket
    int sock;
    if (type == 4)
    {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); // IPv4
    }
    else
    {
        sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6); // IPv6
    }

    if (sock < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Set up the destination address
    struct sockaddr_storage dest;
    memset(&dest, 0, sizeof(dest));

    if (type == 4)
    {
        struct sockaddr_in *dest4 = (struct sockaddr_in *)&dest;
        dest4->sin_family = AF_INET;
        if (inet_pton(AF_INET, address, &dest4->sin_addr) <= 0)
        {
            perror("inet_pton");
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        struct sockaddr_in6 *dest6 = (struct sockaddr_in6 *)&dest;
        dest6->sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, address, &dest6->sin6_addr) <= 0)
        {
            perror("inet_pton");
            exit(EXIT_FAILURE);
        }
    }

    // Register signal handler for clean exit
    signal(SIGINT, handle_signal);

    struct timeval start_time;
    printf("Pinging %s with 64 bytes of data:\n", address);

    // Main loop to send and receive packets
    for (int i = 0; count == -1 || i < count; i++)
    {
        gettimeofday(&start_time, NULL); // Record the start time
        send_ping(sock, (struct sockaddr *)&dest, sizeof(dest), type, i);

        struct pollfd pfd = {.fd = sock, .events = POLLIN};
        int ret = poll(&pfd, 1, TIMEOUT * 1000); // Wait for a response

        if (ret > 0)
        {
            receive_ping(sock, &start_time, i + 1, address); // Process the response
        }
        else if (ret == 0)
        {
            printf("Request timeout for seq=%d\n", i + 1); // Timeout message
        }
        else
        {
            perror("poll");
            break;
        }

        if (!flood)
        {
            sleep(1); // Wait 1 second between packets unless flood mode is enabled
        }
    }

    print_statistics(address); // Print final statistics
    return 0;
}

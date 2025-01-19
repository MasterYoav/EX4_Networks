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

#define MAX_HOPS 30 // Maximum number of hops to trace
#define PROBES_PER_HOP 3 // Number of probes sent per hop
#define TIMEOUT 1 // Timeout for receiving a response in seconds
#define BUFFER_SIZE 1024 // Buffer size for packets

// Function to calculate the checksum for ICMP packets
unsigned short checksum(void *b, int len)
{
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    // Sum all 16-bit words in the buffer
    for (sum = 0; len > 1; len -= 2)
    {
        sum += *buf++;
    }
    if (len == 1) // Add remaining byte if buffer length is odd
    {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF); // Add carry bits
    sum += (sum >> 16); // Handle overflow
    result = ~sum; // Return the one's complement of the sum
    return result;
}

// Function to send an ICMP probe to the destination
void send_probe(int sock, struct sockaddr *dest, int ttl, int seq_num)
{
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);

    struct icmphdr *icmp_hdr = (struct icmphdr *)buffer;
    icmp_hdr->type = ICMP_ECHO; // Echo request type
    icmp_hdr->code = 0; // Code is always 0 for echo requests
    icmp_hdr->checksum = 0;
    icmp_hdr->un.echo.id = getpid(); // Set identifier to the process ID
    icmp_hdr->un.echo.sequence = seq_num; // Set sequence number
    icmp_hdr->checksum = checksum(buffer, sizeof(struct icmphdr)); // Calculate checksum

    // Send the ICMP packet
    if (sendto(sock, buffer, sizeof(struct icmphdr), 0, dest, sizeof(struct sockaddr_in)) < 0)
    {
        perror("sendto"); // Print error if packet sending fails
    }
}

// Function to receive an ICMP response and calculate round-trip time (RTT)
int receive_probe(int sock, struct sockaddr_in *recv_addr, double *rtt)
{
    char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(*recv_addr);
    struct timeval start, end;

    gettimeofday(&start, NULL); // Record the start time

    struct pollfd pfd = {.fd = sock, .events = POLLIN}; // Set up poll for the socket
    int ret = poll(&pfd, 1, TIMEOUT * 1000); // Wait for a response with timeout

    if (ret > 0) // If there is a response
    {
        if (recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)recv_addr, &addr_len) > 0)
        {
            gettimeofday(&end, NULL); // Record the end time
            *rtt = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0; // Calculate RTT in milliseconds
            return 1; // Success
        }
    }

    return 0; // Timeout or error
}

int main(int argc, char *argv[])
{
    // Command-line arguments validation
    if (argc != 3 || strcmp(argv[1], "-a") != 0)
    {
        fprintf(stderr, "Usage: %s -a <address>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *target_ip = argv[2]; // Target IP address
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET; // Set address family to IPv4

    // Convert target IP from string to binary form
    if (inet_pton(AF_INET, target_ip, &dest.sin_addr) <= 0)
    {
        perror("inet_pton"); // Print error if conversion fails
        exit(EXIT_FAILURE);
    }

    // Create a raw socket for sending ICMP packets
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0)
    {
        perror("socket"); // Print error if socket creation fails
        exit(EXIT_FAILURE);
    }

    printf("traceroute to %s, %d hops max\n", target_ip, MAX_HOPS);

    // Loop through TTL values to trace the route
    for (int ttl = 1; ttl <= MAX_HOPS; ttl++)
    {
        setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)); // Set the TTL for the socket

        struct sockaddr_in recv_addr;
        int responses = 0; // Count of received responses
        double total_rtt = 0.0;

        printf("%2d ", ttl); // Print the current TTL value

        for (int probe = 0; probe < PROBES_PER_HOP; probe++)
        {
            send_probe(sock, (struct sockaddr *)&dest, ttl, probe + 1); // Send a probe

            double rtt = 0.0;
            int result = receive_probe(sock, &recv_addr, &rtt); // Receive the response

            if (result == 1) // If a response is received
            {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &recv_addr.sin_addr, ip_str, sizeof(ip_str)); // Convert IP address to string
                if (probe == 0)
                    printf("%s ", ip_str); // Print the IP address once per TTL
                printf("%.3fms ", rtt); // Print the RTT for this probe
                total_rtt += rtt;
                responses++;
            }
            else
            {
                printf("* "); // Print * for no response
            }
        }

        printf("\n");

        // Check if the destination is reached
        if (responses > 0 && recv_addr.sin_addr.s_addr == dest.sin_addr.s_addr)
        {
            printf("Reached destination\n");
            break;
        }

        // If maximum hops are reached and no response
        if (ttl == MAX_HOPS)
        {
            printf("Destination unreachable\n");
        }
    }

    close(sock); // Close the socket
    return 0;
}

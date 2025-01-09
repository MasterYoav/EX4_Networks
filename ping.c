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
#include <stdint.h> // For fixed-width integer types like uint8_t and uint16_t

#define TIMEOUT 10       // Timeout in seconds for waiting for a reply
#define BUFFER_SIZE 1024 // Size of the buffer to store packets

// ICMP Header for IPv4 (manual definition for compatibility)
struct icmphdr
{
    uint8_t type;      // Message type (e.g., Echo Request = 8, Echo Reply = 0)
    uint8_t code;      // Message code (e.g., 0 for most ICMP types)
    uint16_t checksum; // Checksum for error detection
    union
    { // Union for mutual-exclusive fields
        struct
        {                      // Echo-specific fields
            uint16_t id;       // Identifier for matching requests/replies
            uint16_t sequence; // Sequence number for tracking packets
        } echo;
        uint32_t gateway; // Gateway address for Redirect messages
        struct
        { // Fragmentation-related fields
            uint16_t unused_field;
            uint16_t mtu;
        } frag;
    } un;
};

// Variables to track statistics
int packets_sent = 0;     // Number of packets sent
int packets_received = 0; // Number of packets received
long total_rtt = 0;       // Total round-trip time (RTT)
long min_rtt = 1000000;   // Minimum RTT
long max_rtt = 0;         // Maximum RTT

// Function to print ping statistics at the end
void print_statistics()
{
    printf("\n--- Ping Statistics ---\n");
    printf("%d packets transmitted, %d received, %.2f%% packet loss\n",
           packets_sent, packets_received,
           ((packets_sent - packets_received) * 100.0) / packets_sent);
    if (packets_received > 0)
    {
        printf("RTT min/avg/max = %ld/%.2f/%ld ms\n",
               min_rtt, (double)total_rtt / packets_received, max_rtt);
    }
    exit(0); // End the program
}

// Signal handler to print statistics on Ctrl+C
void handle_signal(int sig)
{
    if (sig == SIGINT)
    { // Check if the signal is Ctrl+C (SIGINT)
        print_statistics();
    }
}

// Function to calculate checksum (used for error detection in ICMP headers)
unsigned short checksum(void *b, int len)
{
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    // Sum up 16-bit words
    for (sum = 0; len > 1; len -= 2)
        sum += *buf++; // Adds the value at `buf` to `sum`, then increments `buf` to the next address.
    if (len == 1)      // Add any leftover byte
        sum += *(unsigned char *)buf;

    // Fold 32-bit sum into 16 bits and return
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum; // Invert the sum for checksum
    return result;
}

// Function to send an ICMP ping packet
void send_ping(int sock, struct sockaddr *addr, socklen_t addrlen, int type, int seq_num)
{
    char buffer[BUFFER_SIZE];       // Buffer to store the ICMP packet
    memset(buffer, 0, BUFFER_SIZE); // Clear the buffer

    if (type == 4)
    { // IPv4 ICMP packet
        struct icmphdr *icmp_hdr = (struct icmphdr *)buffer;
        icmp_hdr->type = ICMP_ECHO;                                    // Set type to Echo Request
        icmp_hdr->code = 0;                                            // Code is 0 for Echo Request
        icmp_hdr->checksum = 0;                                        // Checksum starts at 0
        icmp_hdr->un.echo.id = getpid();                               // Use process ID as identifier
        icmp_hdr->un.echo.sequence = seq_num;                          // Set sequence number
        icmp_hdr->checksum = checksum(buffer, sizeof(struct icmphdr)); // Calculate checksum
    }
    else if (type == 6)
    { // IPv6 ICMP packet
        struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)buffer;
        icmp6_hdr->icmp6_type = ICMP6_ECHO_REQUEST; // Echo Request for IPv6
        icmp6_hdr->icmp6_code = 0;                  // Code is 0
        icmp6_hdr->icmp6_id = getpid();             // Use process ID as identifier
        icmp6_hdr->icmp6_seq = seq_num;             // Set sequence number
    }

    // Send the packet using sendto()
    if (sendto(sock, buffer, sizeof(struct icmphdr), 0, addr, addrlen) <= 0)
    {
        perror("sendto fail"); // Print error if sendto() fails
    }
    else
    {
        packets_sent++; // Increment sent packets count
    }
}

// Function to receive a ping response
void receive_ping(int sock, struct timeval *start_time)
{
    char buffer[BUFFER_SIZE]; // Buffer to store the received packet
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    struct timeval end_time;

    // Receive the packet using recvfrom()
    if (recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&addr, &addrlen) <= 0)
    {
        perror("recvfrom fail"); // Print error if recvfrom() fails
        return;
    }

    gettimeofday(&end_time, NULL); // Record the time of receiving the response

    // Calculate the round-trip time (RTT)
    long rtt = (end_time.tv_sec - start_time->tv_sec) * 1000;
    rtt += (end_time.tv_usec - start_time->tv_usec) / 1000;

    packets_received++; // Increment received packets count
    total_rtt += rtt;   // Add to total RTT
    if (rtt < min_rtt)  // Update minimum RTT
        min_rtt = rtt;
    if (rtt > max_rtt) // Update maximum RTT
        max_rtt = rtt;

    printf("Reply received: RTT=%ld ms\n", rtt); // Print RTT
}

// Main function
int main(int argc, char *argv[])
{
    int opt;              // option
    char *address = NULL; // Target address
    int type = 0;         // Protocol type (4 for IPv4, 6 for IPv6)
    int count = -1;       // Number of packets to send (-1 for infinite)
    int flood = 0;        // Flood mode flag

    // Parse command-line arguments using getopt()
    while ((opt = getopt(argc, argv, "a:t:c:f")) != -1)
    {
        switch (opt)
        {
        case 'a': // Target address
            address = optarg;
            break;
        case 't': // Protocol type
            type = atoi(optarg);
            break;
        case 'c': // Count of packets
            count = atoi(optarg);
            break;
        case 'f': // Flood mode
            flood = 1;
            break;
        default:
            fprintf(stderr, "Usage: %s -a <address> -t <4|6> [-c count] [-f]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (!address || (type != 4 && type != 6))
    {
        fprintf(stderr, "Usage: %s -a <address> -t <4|6> [-c count] [-f]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int sock;
    if (type == 4)
    { // IPv4 socket
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    }
    else
    { // IPv6 socket
        sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    }

    if (sock < 0)
    { // Check if socket creation failed
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_storage dest;
    memset(&dest, 0, sizeof(dest)); // Clear the destination address

    if (type == 4)
    { // IPv4 address setup
        struct sockaddr_in *dest4 = (struct sockaddr_in *)&dest;
        dest4->sin_family = AF_INET;
        if (inet_pton(AF_INET, address, &dest4->sin_addr) <= 0) // cast IPaddr to binary IP
        {
            perror("inet_pton fail");
            exit(EXIT_FAILURE);
        }
    }
    else
    { // IPv6 address setup
        struct sockaddr_in6 *dest6 = (struct sockaddr_in6 *)&dest;
        dest6->sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, address, &dest6->sin6_addr) <= 0)
        {
            perror("inet_pton v6 fail");
            exit(EXIT_FAILURE);
        }
    }

    signal(SIGINT, handle_signal); // Set up signal handler for Ctrl+C

    struct timeval start_time;

    // Main loop to send and receive packets
    for (int i = 0; count == -1 || i < count; i++)
    {
        gettimeofday(&start_time, NULL); // Record the start time
        send_ping(sock, (struct sockaddr *)&dest, sizeof(dest), type, i);

        struct pollfd pfd = {.fd = sock, .events = POLLIN};
        int ret = poll(&pfd, 1, TIMEOUT * 1000); // Wait for response or timeout

        if (ret > 0)
        {
            receive_ping(sock, &start_time);
        }
        else if (ret == 0)
        {
            printf("Request timeout for seq=%d\n", i); // Timeout message
        }
        else
        {
            perror("poll error"); // Error in poll()
            break;
        }

        if (!flood)
        {
            sleep(1); // Wait 1 second before sending the next packet
        }
    }

    print_statistics(); // Print final statistics
    return 0;
}
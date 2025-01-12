#ifndef PING_H
#define PING_H

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


// Constants
#define TIMEOUT 10 // Timeout in seconds
#define BUFFER_SIZE 1024

// Function prototypes
void print_statistics(const char *address);
void handle_signal(int sig);
unsigned short checksum(void *b, int len);
void send_ping(int sock, struct sockaddr *addr, socklen_t addrlen, int type, int seq_num);
void receive_ping(int sock, struct timeval *start_time, int seq_num, const char *address);

#endif
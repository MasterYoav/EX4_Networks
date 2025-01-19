#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>

void send_probe(int sock, struct sockaddr *dest, int ttl, int seq_num);
int receive_probe(int sock, struct sockaddr_in *recv_addr, double *rtt);
unsigned short checksum(void *b, int len);

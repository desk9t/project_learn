#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <sys/types.h>
#include <stddef.h>

//  生成 BPF 指令集 -> 获取输出文件 -> 使用转换脚本 -> 输出为 C 可用的 sock_filter
/* BPF过滤器 - 只捕获ICMP数据包 */
/* BPF过滤器：仅捕获ICMP协议数据包 */
static struct sock_filter icmp_filter[] = {
    /* 加载以太网类型字段(2字节) */
    { .code = BPF_LD | BPF_H | BPF_ABS, .jt = 0, .jf = 0, .k = offsetof(struct ethhdr, h_proto) },
    /* 检查是否为IPv4包(0x0800) */
    { .code = BPF_JMP | BPF_JEQ | BPF_K, .jt = 0, .jf = 3, .k = ETH_P_IP },
    /* 加载IP协议字段(1字节) */
    { .code = BPF_LD | BPF_B | BPF_ABS, .jt = 0, .jf = 0, .k = ETH_HLEN + offsetof(struct iphdr, protocol) },
    /* 检查是否为ICMP协议(1) */
    { .code = BPF_JMP | BPF_JEQ | BPF_K, .jt = 0, .jf = 1, .k = IPPROTO_ICMP },
    /* 接受ICMP数据包 */
    { .code = BPF_RET | BPF_K, .jt = 0, .jf = 0, .k = 0xFFFF },
    /* 拒绝其他所有数据包 */
    { .code = BPF_RET | BPF_K, .jt = 0, .jf = 0, .k = 0 }
};
/*
  标志	  值	             作用
BPF_LD	0x00	加载指令：将数据存入 BPF 累加器（寄存器 A）
BPF_H	0x08	操作半字（2 字节）：读取 2 字节数据（ethhdr->h_proto 是 2 字节）
BPF_ABS	0x20	绝对偏移量：从数据包开头计算偏移量
BPF_JMP	0x10	跳转指令：根据条件跳转到指定位置
BPF_JEQ	0x00	相等跳转：如果条件成立，则跳转到指定位置
BPF_K	0x00	常数：与寄存器 A 中的值进行比较
BPF_RET	0x06	返回指令：返回 BPF 程序的结果
*/
/*
code：操作码（如加载、跳转、返回）。
jt：条件为真时的跳转目标（偏移量）。
jf：条件为假时的跳转目标（偏移量）。
k：常数值或偏移量。
*/

/*
6
40 0 0 12
21 0 3 2048
48 0 0 23
21 0 1 1
6 0 0 262144
6 0 0 0
*/

static struct sock_fprog icmp_fprog = {
    .len = sizeof(icmp_filter) / sizeof(struct sock_filter),
    .filter = icmp_filter
};

/* 打印MAC地址 */
void print_mac_address(unsigned char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int main() {
    int sock;
    char buffer[2048];
    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);

    /* 创建原始套接字 */
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    
    /* 附加BPF过滤器 */
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, 
                   &icmp_fprog, sizeof(icmp_fprog)) < 0) {
        perror("setsockopt(SO_ATTACH_FILTER)");
        close(sock);
        exit(EXIT_FAILURE);
    }
    
    printf("Starting ICMP packet tracer...\n");
    
    while (1) {
        int data_size = recvfrom(sock, buffer, sizeof(buffer), 0,
                                 &saddr, &saddr_len);
        if (data_size < 0) {
            perror("recvfrom");
            break;
        }
    
        /* 检查数据包长度 */
        if (data_size < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
            printf("Incomplete packet received, size: %d\n", data_size);
            continue;
        }
    
        /* 解析以太网头部 */
        struct ethhdr *eth = (struct ethhdr *)buffer;
        printf("\n=== Packet Captured ===\n");
        printf("Ethernet Header:\n");
        printf("  Source MAC: ");
        print_mac_address(eth->h_source);
        printf("\n");
        printf("  Destination MAC: ");
        print_mac_address(eth->h_dest);
        printf("\n");
        printf("  Protocol: 0x%04x (%s)\n", 
               ntohs(eth->h_proto), 
               ntohs(eth->h_proto) == ETH_P_IP ? "IP" : "Unknown");
    
        /* 解析IP头部 */
        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        if (data_size < sizeof(struct ethhdr) + (ip->ihl * 4)) {
            printf("Incomplete IP header, size: %d\n", data_size);
            continue;
        }
    
        printf("IP Header:\n");
        printf("  Version: %d\n", ip->version);
        printf("  Header Length: %d bytes\n", ip->ihl * 4);
        printf("  TOS: 0x%02x\n", ip->tos);
        printf("  Total Length: %d bytes\n", ntohs(ip->tot_len));
        printf("  Identification: 0x%04x\n", ntohs(ip->id));
        printf("  Fragment Offset: %d\n", ntohs(ip->frag_off) & 0x1FFF);
        printf("  TTL: %d\n", ip->ttl);
        printf("  Protocol: %d (%s)\n", 
               ip->protocol, 
               ip->protocol == IPPROTO_ICMP ? "ICMP" : "Unknown");
        printf("  Checksum: 0x%04x\n", ntohs(ip->check));
        printf("  Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
        printf("  Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));
    
        /* 解析ICMP头部 */
        struct icmphdr *icmp = (struct icmphdr *)(buffer + sizeof(struct ethhdr) + (ip->ihl * 4));
        if (data_size < sizeof(struct ethhdr) + (ip->ihl * 4) + sizeof(struct icmphdr)) {
            printf("Incomplete ICMP header, size: %d\n", data_size);
            continue;
        }
    
        printf("ICMP Header:\n");
        if (icmp->type == ICMP_ECHO)
            printf("  Type: Echo Request (Ping) (%d)\n", icmp->type);
        else if (icmp->type == ICMP_ECHOREPLY)
            printf("  Type: Echo Reply (Pong) (%d)\n", icmp->type);
        else
            printf("  Type: %d\n", icmp->type);
        printf("  Code: %d\n", icmp->code);
        printf("  Checksum: 0x%04x\n", ntohs(icmp->checksum));
        printf("  ID: %d\n", ntohs(icmp->un.echo.id));
        printf("  Sequence: %d\n", ntohs(icmp->un.echo.sequence));
    }
    
    close(sock);
    return 0;

}

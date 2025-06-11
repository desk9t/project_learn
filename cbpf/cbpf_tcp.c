//编译得 gcc -std=c99 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/tcp.h> /* 确保 tcphdr 定义 */
#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <sys/types.h>
#include <stddef.h>

/* BPF 过滤器：捕获所有 TCP 数据包 */
static struct sock_filter tcp_filter[] = {
    /* 0: 加载以太网类型字段（2字节） */
    { BPF_LD | BPF_H | BPF_ABS, 0, 0, offsetof(struct ethhdr, h_proto) },
    /* 1: 检查是否为 IPv4 包（0x0800） */
    { BPF_JMP | BPF_JEQ | BPF_K, 0, 3, ETH_P_IP },
    /* 2: 加载 IP 协议字段（1字节） */
    { BPF_LD | BPF_B | BPF_ABS, 0, 0, ETH_HLEN + 9 }, /* protocol 位于 IP 头部偏移 9 */
    /* 3: 检查是否为 TCP 协议（6） */
    { BPF_JMP | BPF_JEQ | BPF_K, 0, 1, IPPROTO_TCP },
    /* 4: 接受匹配的数据包 */
    { BPF_RET | BPF_K, 0, 0, 0xFFFF },
    /* 5: 拒绝其他所有数据包 */
    { BPF_RET | BPF_K, 0, 0, 0 }
};

static struct sock_fprog tcp_fprog = {
    .len = sizeof(tcp_filter) / sizeof(struct sock_filter),
    .filter = tcp_filter
};

/* 打印 MAC 地址 */
void print_mac_address(unsigned char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* 打印 TCP Payload（文本和十六进制格式） */
void print_payload(const unsigned char *payload, int payload_len) {
    printf("TCP Payload (%d 字节):\n", payload_len);
    /* 尝试作为文本打印（如果包含可打印字符） */
    printf("  文本格式: ");
    for (int i = 0; i < payload_len; i++) {
        if (payload[i] >= 32 && payload[i] <= 126) {
            printf("%c", payload[i]);
        } else {
            printf(".");
        }
    }
    printf("\n");
    /* 按十六进制打印 */
    printf("  十六进制格式:\n");
    for (int j = 0; j < payload_len; j++) {
        if (j % 16 == 0) printf("    ");
        printf("%02x ", payload[j]);
        if ((j + 1) % 16 == 0) printf("\n");
    }
    if (payload_len % 16 != 0) printf("\n");
}

int main() {
    int sock;
    char buffer[2048];
    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);

    /* 创建原始套接字 */
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("套接字创建失败");
        exit(EXIT_FAILURE);
    }

    /* 附加 BPF 过滤器 */
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER,
                   &tcp_fprog, sizeof(tcp_fprog)) < 0) {
        perror("设置 BPF 过滤器失败");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("启动 TCP 数据包捕获，目标：所有 TCP 数据包...\n");

    while (1) {
        int data_size = recvfrom(sock, buffer, sizeof(buffer), 0,
                                 &saddr, &saddr_len);
        if (data_size < 0) {
            perror("接收数据失败");
            break;
        }

        /* 检查数据包长度 */
        if (data_size < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
            printf("接收到不完整数据包，大小：%d\n", data_size);
            continue;
        }

        /* 解析以太网头部 */
        struct ethhdr *eth = (struct ethhdr *)buffer;
        printf("\n=== 捕获到数据包 ===\n");
        printf("以太网头部:\n");
        printf("  源 MAC: ");
        print_mac_address(eth->h_source);
        printf("\n");
        printf("  目的 MAC: ");
        print_mac_address(eth->h_dest);
        printf("\n");
        printf("  协议: 0x%04x (%s)\n",
               ntohs(eth->h_proto),
               ntohs(eth->h_proto) == ETH_P_IP ? "IP" : "未知");

        /* 解析 IP 头部 */
        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        if (data_size < sizeof(struct ethhdr) + (ip->ihl * 4)) {
            printf("不完整 IP 头部，大小：%d\n", data_size);
            continue;
        }

        printf("IP 头部:\n");
        printf("  版本: %d\n", ip->version);
        printf("  头部长度: %d 字节\n", ip->ihl * 4);
        printf("  服务类型: 0x%02x\n", ip->tos);
        printf("  总长度: %d 字节\n", ntohs(ip->tot_len));
        printf("  标识: 0x%04x\n", ntohs(ip->id));
        printf("  分片偏移: %d\n", ntohs(ip->frag_off) & 0x1FFF);
        printf("  生存时间: %d\n", ip->ttl);
        printf("  协议: %d (%s)\n",
               ip->protocol,
               ip->protocol == IPPROTO_TCP ? "TCP" : "未知");
        printf("  校验和: 0x%04x\n", ntohs(ip->check));
        printf("  源 IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
        printf("  目的 IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));

        /* 解析 TCP 头部 */
        struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + (ip->ihl * 4));
        if (data_size < sizeof(struct ethhdr) + (ip->ihl * 4) + sizeof(struct tcphdr)) {
            printf("不完整 TCP 头部，大小：%d\n", data_size);
            continue;
        }

        printf("TCP 头部:\n");
        printf("  源端口: %d\n", ntohs(tcp->source));
        printf("  目的端口: %d\n", ntohs(tcp->dest));
        printf("  序列号: %u\n", ntohl(tcp->seq));
        printf("  确认号: %u\n", ntohl(tcp->ack_seq));
        printf("  头部长度: %d 字节\n", tcp->doff * 4);
        printf("  标志: (");
        if (tcp->urg) printf("URG ");
        if (tcp->ack) printf("ACK ");
        if (tcp->psh) printf("PSH ");
        if (tcp->rst) printf("RST ");
        if (tcp->syn) printf("SYN ");
        if (tcp->fin) printf("FIN ");
        printf(")\n");
        printf("  窗口大小: %d\n", ntohs(tcp->window));
        printf("  校验和: 0x%04x\n", ntohs(tcp->check));
        printf("  紧急指针: %d\n", ntohs(tcp->urg_ptr));

        /* 计算并打印 payload 长度 */
        int ip_header_len = ip->ihl * 4;
        int tcp_header_len = tcp->doff * 4;
        int payload_len = ntohs(ip->tot_len) - ip_header_len - tcp_header_len;
        printf("  Payload 长度: %d 字节\n", payload_len);

        /* 解析并打印 TCP Payload */
        if (payload_len > 0) {
            unsigned char *payload = (unsigned char *)(buffer + sizeof(struct ethhdr) + ip_header_len + tcp_header_len);
            print_payload(payload, payload_len);
        }
    }

    close(sock);
    return 0;
}

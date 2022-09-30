#pragma once

/* структура ip заголовка */
struct sniff_ip {
    u_char ip_vhl;  /* версия << 4 | длина заголовка >> 2 */
    u_char ip_tos;  /* тип службы */
    u_short ip_len;  /* общая длина */
    u_short ip_id;  /* идентификатор */
    u_short ip_off;  /* поле фрагмента смещения */
#define IP_RF 0x8000  /* reserved флаг фрагмента */
#define IP_DF 0x4000  /* dont флаг фрагмента */
#define IP_MF 0x2000  /* more флаг фрагмента */
#define IP_OFFMASK 0x1fff /* маска для битов фрагмента */
    u_char ip_ttl;  /* время жизни */
    u_char ip_p;  /* протокол */
    u_short ip_sum;  /* контрольная сумма */
    struct in_addr ip_src, ip_dst;  /* адрес источника и адрес назначения */
};
#define IP_HL(ip)  (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)  (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;
struct sniff_tcp {
    u_short th_sport; /* порт источника */
    u_short th_dport; /* порт назначения */
    tcp_seq th_seq;  /* номер последовательности */
    tcp_seq th_ack;  /* номер подтверждения */
    u_char th_offx2; /* смещение данных, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;  /* окно */
    u_short th_sum;  /* контрольная сумма */
    u_short th_urp;  /* экстренный указатель */
};

/* UDP header*/
typedef struct udp_header {
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;

/* ICMP header */
typedef struct ICMPHeader
{
    unsigned char   type;           // тип ICMP- пакета
    unsigned char   code;           // код ICMP- пакета 
    unsigned short  crc;           // контрольная сумма 
    union {
        struct { unsigned char  uc1, uc2, uc3, uc4; } s_uc;
        struct { unsigned short us1, us2; } s_us;
        unsigned long s_ul;
    } s_icmp;               // зависит от типа
}ICMPHeader;

/* класс с характеристиками tcp */
class ctp {
public:
    ctp(tcp_seq s, tcp_seq a, u_char f, u_short w, u_short su) : seq(s), ack(a), flags(f), win(w), sum(su) {}
    tcp_seq seq;  // номер последовательности
    tcp_seq ack;  // номер подтверждения
    u_char flags;
    u_short win;  // окно
    u_short sum;  /* контрольная сумма*/
};

void rewrite(const char* path)
{
    pcap_t* re_pcap = pcap_open_dead(DLT_EN10MB, 65535); /* переменная для новых файлов с пакетами */
    pcap_dumper_t* rewrite_pcap = pcap_dump_open(re_pcap, path); /* открываем ее */
}
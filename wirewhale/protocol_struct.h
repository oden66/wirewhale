#ifndef HEADERSTRUCT_H
#define HEADERSTRUCT_H
#include "qglobal.h"

//数据类型长度大于1字节使用qFromBigEndian()将网络顺序转为主机顺序

//ip地址
typedef struct ip_address{
    quint8 byte1;
    quint8 byte2;
    quint8 byte3;
    quint8 byte4;
}ip_address;

//以太网头部
typedef struct ethernet_header{
    quint8 DesMac[6];               //目标MAC地址
    quint8 SrcMac[6];               //源MAC地址
    quint16 Type;                   //类型
}ethernet_header;

//arp
typedef struct arp {
    quint16 htype;                  //硬件类型
    quint16 ptype;                  //协议类型
    quint8 hlen;                    //硬件地址长度
    quint8 plen;                    //协议地址长度
    quint16 oper;                   //操作码
    quint8 sha[6];                  //发送方硬件地址
    ip_address spa;                 //发送方协议地址
    quint8 tha[6];                  //目标硬件地址
    ip_address tpa;                 //目标协议地址
}arp;

//ipv4头部
typedef struct ip_header{
    quint8 ver_ihl;                 //版本+首部长度
    quint8 tos;                     //区分服务
    quint16 tl;                     //总长度
    quint16 id;                     //标识
    quint16 flags;                  //标志+片偏移
    quint8 ttl;                     //生存时间
    quint8 protocol;                //协议
    quint16 sum;                    //首部校验和
    ip_address srcaddr;             //源地址
    ip_address desaddr;             //目的地址
}ip_header;

//tcp头部
typedef struct tcp_header {
    quint16 srcport;                //源端口
    quint16 desport;                //目的端口
    quint32 seq;                    //序号
    quint32 ack;                    //确认号
    quint8 dtoff;                   //数据偏移(4)
    quint8 flags;                   //标志符(12)
    quint16 win;                    //窗口
    quint16 sum;                    //检验和
    quint16 upt;                    //紧急指针
}tcp_header;

//udp头部
typedef struct udp_header {
    quint16 srcport;                //源端口
    quint16 desport;                //目的端口
    quint16 len;                    //长度
    quint16 sum;                    //校验和
}udp_header;

//icmp前4字节
typedef struct icmp_header {
    quint8 type;                    //类型
    quint8 code;                    //代码
    quint16 sum;                    //校验和
}icmp_header;

//icmp type=3、5、11
typedef struct icpm_3_5_11 {
    quint32 unuse;                  //未使用
}icmp_un;

//icmp type=8或0
typedef struct icmp_8w0 {
    quint16 id;                     //id号
    quint16 seq;                    //序列号
}icmp_8w0;

//dns头部
typedef struct dns_header{
    quint16 id;                     //事务ID
    quint16 flags;                  //标志
    quint16 qst;                    //问题记录数
    quint16 asr;                    //回答记录数
    quint16 aut;                    //授权记录数
    quint16 add;                    //附加记录数
}dns_header;

#endif // HEADERSTRUCT_H

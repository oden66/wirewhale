#include "interpret_hanlder.h"

Interpret_Hanlder::Interpret_Hanlder(QObject *parent)
    : QObject{parent}
{
    pkt_data=nullptr;
    isICMP=false;
}

QString Interpret_Hanlder::IptoQStr(ip_address ip)
{
    return QString::number(ip.byte1)+"."+QString::number(ip.byte2)+"."+QString::number(ip.byte3)+"."+QString::number(ip.byte4);
}

QString Interpret_Hanlder::HwtoQStr(quint8* hw)
{
    QString str;
    quint8* temp=hw;
    for(int i=0;i<5;i++,temp++)
    {
        str+=QString::number(*temp,16)+":";
    }
    str+=QString::number(*temp,16);
    return str;
}

void Interpret_Hanlder::PacketList(int count,QString time,struct pcap_pkthdr *header,const quint8 *pktdata)
{
    QStringList list;
    this->pkt_data=pktdata;
    this->lpacket=header->len;
    list<<QString::number(count);
    list<<time;
    ethernet_header* ethlayer=(ethernet_header*)pkt_data;
//    lpacket+=14;
    quint16 type=qFromBigEndian(ethlayer->Type);
    if(type==0x0800)                                                        //IPv4
    {
        pkt_data+=14;
        ip_header* iplayer=(ip_header*)(pkt_data);
        quint8 protocol=iplayer->protocol;
        int lheader=(iplayer->ver_ihl&0x0f)*4;
        list<<IptoQStr(iplayer->srcaddr);
        list<<IptoQStr(iplayer->desaddr);
//        lpacket+=qFromBigEndian(iplayer->tl);
        if(protocol==0x01)                                                  //ICMP
        {
            list<<"ICMP";
            list<<QString::number(lpacket);
            pkt_data+=lheader;
            IcmpList(list);
        }
        else if(protocol==0x06)                                             //TCP
        {
            list<<"TCP";
            list<<QString::number(lpacket);
            pkt_data+=lheader;
            TcpList(list);
        }
        else if(protocol==0x11)                                             //UDP
        {
            pkt_data+=lheader;
            UdpList(list);
        }
        else
        {
            list<<"Unkown";
            list<<QString::number(lpacket);
        }
    }
    else if(type==0x0806)                                                   //ARP
    {
        ArpList(list);
    }
    else
    {

    }
    emit ListInfo(list);
}

void Interpret_Hanlder::ArpList(QStringList &list)
{
    arp* arplayer=(arp*)pkt_data;
    quint8* sha=arplayer->sha;
    quint8* tha=arplayer->tha;
    quint16 oper=qFromBigEndian(arplayer->oper);
    list<<HwtoQStr(sha);
    list<<HwtoQStr(tha);
    list<<"ARP";
//    lpacket+=28;
    ip_address spa=arplayer->spa;
    ip_address tpa=arplayer->tpa;
    if(oper==1)
    {
        list<<QString::number(lpacket);
        list<<"Who has "+IptoQStr(tpa)+"? "+"Tell "+IptoQStr(spa);
    }
    else
    {
        list<<QString::number(lpacket+18);
        list<<IptoQStr(spa)+" is at "+HwtoQStr(sha);
    }
}

void Interpret_Hanlder::IcmpList(QStringList &list)
{
    icmp_header* ih4=(icmp_header*)pkt_data;
    switch(ih4->type)
    {
    case 3:
        list<<"Destination unreachable (Code: "+QString::number(ih4->code)+")";
        break;
    case 11:
        list<<"Time exceeded (Code: "+QString::number(ih4->code)+")";
        break;
    case 5:
        list<<"Redirect (Code: "+QString::number(ih4->code)+")";
        break;
    case 8:
    {
        if(list[5].toInt()<64)
        {
            list[5]=QString::number(64);
        }
        icmp_8w0* i8=(icmp_8w0*)(pkt_data+4);
        list<<"Echo request id="+QString::number(qFromBigEndian(i8->id));
    }
        break;
    case 0:
    {
        if(list[5].toInt()<64)
        {
            list[5]=QString::number(64);
        }
        icmp_8w0* i8=(icmp_8w0*)(pkt_data+4);
        list<<"Echo reply id="+QString::number(qFromBigEndian(i8->id));
    }
        break;
    default:
        list<<"Other";
        break;
    }
}

void Interpret_Hanlder::TcpList(QStringList &list)
{
    tcp_header* tcph=(tcp_header*)pkt_data;
    quint16 srcport=qFromBigEndian(tcph->srcport);
    quint16 desport=qFromBigEndian(tcph->desport);
    list<<QString::number(srcport)+" -> "+QString::number(desport);
}

void Interpret_Hanlder::UdpList(QStringList &list)
{
    udp_header* udph=(udp_header*)pkt_data;
    quint16 srcport=qFromBigEndian(udph->srcport);
    quint16 desport=qFromBigEndian(udph->desport);
    quint16 len=qFromBigEndian(udph->len);
    if(srcport==53||desport==53)
    {
        list<<"DNS";
        list<<QString::number(lpacket);
        dns_header* dnsh=(dns_header*)(pkt_data+8);
        quint16 flags=qFromBigEndian(dnsh->flags);
        if(flags==0x0100)
        {
            list<<"Standard query 0x"+QString::number(qFromBigEndian(dnsh->id),16);
        }
        else if(flags==0x8180)
        {
            list<<"Standard query response 0x"+QString::number(qFromBigEndian(dnsh->id),16);
        }
    }
    else
    {
        list<<"UDP";
        list<<QString::number(lpacket);
        list<<QString::number(srcport)+" -> "+QString::number(desport)+" Len="+QString::number(len-8);
    }
}

void Interpret_Hanlder::PacketAnalyze(quint32 length, const quint8 *pktdata)
{
    this->lpacket=length;
    this->pkt_data=pktdata;
    QList<QStandardItem*> prolayer;
    ethernet_header* ethlayer=(ethernet_header*)pkt_data;
    QStandardItem* eth=new QStandardItem("Ethernet II");
    QStandardItem* des=new QStandardItem("MAC 目的地址: "+HwtoQStr(ethlayer->DesMac));
    eth->appendRow(des);
    QStandardItem* src=new QStandardItem("MAC 源地址: "+HwtoQStr(ethlayer->SrcMac));
    eth->appendRow(src);
    quint16 type=qFromBigEndian(ethlayer->Type);
    pkt_data+=14;
    lpacket-=14;
    if(type==0x0800)
    {
        QStandardItem* typesi=new QStandardItem("类型: IPv4");
        eth->appendRow(typesi);
        prolayer<<eth;
        IPv4Analyze(prolayer);
    }
    else if(type==0x0806)
    {
        QStandardItem* typesi=new QStandardItem("类型: ARP");
        eth->appendRow(typesi);
        prolayer<<eth;
        if(lpacket<46)
        {
            prolayer[0]->appendRow(new QStandardItem("Padding: "+QString::number(lpacket-28)));
        }
        ArpAnalyze(prolayer);
    }
    else
    {
        QStandardItem* typesi=new QStandardItem(QString::number(type,16));
        eth->appendRow(typesi);
        prolayer<<eth;
    }
    emit AnalyzeSignal(prolayer);
}

void Interpret_Hanlder::ArpAnalyze(QList<QStandardItem *> &prolayer)
{
    arp* arplayer=(arp*)pkt_data;
    QStandardItem* arpsi=new QStandardItem("ARP");
    QStandardItem* htype=new QStandardItem("硬件类型: "+QString::number(qFromBigEndian(arplayer->htype)));
    QStandardItem* ptype =new QStandardItem("协议类型: "+QString::number(qFromBigEndian(arplayer->ptype),16));
    if(qFromBigEndian(arplayer->ptype)==0x0800)
    {
        ptype->setText("协议类型: IPv4 (0x0800)");
    }
    QStandardItem* hlen=new QStandardItem("硬件地址长度: "+QString::number(arplayer->hlen));
    QStandardItem* plen=new QStandardItem("协议地址长度: "+QString::number(arplayer->plen));
    QStandardItem* oper=new QStandardItem("操作码: "+QString::number(qFromBigEndian(arplayer->oper),16));
    if(qFromBigEndian(arplayer->oper)==1)
    {
        oper->setText("操作码: 请求 (1)");
    }
    else if(qFromBigEndian(arplayer->oper)==2)
    {
        oper->setText("操作码: 回复 (2)");
    }
    QStandardItem* sha=new QStandardItem("发送方硬件地址: "+HwtoQStr(arplayer->sha));
    QStandardItem* spa=new QStandardItem("发送方IP: "+IptoQStr(arplayer->spa));
    QStandardItem* tha=new QStandardItem("目标硬件地址: "+HwtoQStr(arplayer->tha));
    QStandardItem* tpa=new QStandardItem("目标IP"+IptoQStr(arplayer->tpa));
    arpsi->appendRows(QList<QStandardItem*>()<<htype<<ptype<<hlen<<plen<<oper<<sha<<spa<<tha<<tpa);
    prolayer.append(arpsi);
}

void Interpret_Hanlder::IPv4Analyze(QList<QStandardItem *> &prolayer)
{
    ip_header* iplayer=(ip_header*)(pkt_data);
    QStandardItem* ipv4=new QStandardItem("IPv4");
    QStandardItem* ihl=new QStandardItem("首部长度: "+QString::number((iplayer->ver_ihl&0x0f)*4)+" bytes");
    QStandardItem* ver=new QStandardItem("版本: "+QString::number((iplayer->ver_ihl&0xf0)>>4));
    QStandardItem* tos=new QStandardItem("区分服务: 0x"+QString::number((iplayer->tos),16));
    QStandardItem* tl=new QStandardItem("总长度: "+QString::number(qFromBigEndian(iplayer->tl)));
    QStandardItem* id=new QStandardItem("标识符: 0x"+QString::number(qFromBigEndian(iplayer->id),16));
    QStandardItem* flags=new QStandardItem("标志和分片偏移: 0x"+QString::number(qFromBigEndian(iplayer->flags),16));
    QStandardItem* ttl=new QStandardItem("生存时间: "+QString::number(iplayer->ttl));
    quint8 protocol=iplayer->protocol;
    QStandardItem* pro=new QStandardItem("协议类型: 0x"+QString::number(protocol,16));
    if(protocol==0x01)
    {
        pro->setText("协议类型: ICMP (0x01)");
    }
    else if(protocol==0x06)
    {
        pro->setText("协议类型: TCP (0x06)");
    }
    else if(protocol==0x11)
    {
        pro->setText("协议类型: UDP (0x11)");
    }
   QStandardItem* sum=new QStandardItem("首部校验和: 0x"+QString::number(qFromBigEndian(iplayer->sum),16));
   QStandardItem* src=new QStandardItem("源地址: "+IptoQStr(iplayer->srcaddr));
   QStandardItem* des=new QStandardItem("目的地址: "+IptoQStr(iplayer->desaddr));
   ipv4->appendRows(QList<QStandardItem*>()<<ver<<ihl<<tos<<tl<<id<<flags<<ttl<<pro<<sum<<src<<des);
   prolayer.append(ipv4);
   pkt_data+=(iplayer->ver_ihl&0x0f)*4;
   lpacket-=(iplayer->ver_ihl&0x0f)*4;
   if(protocol==0x01)
   {
       IcmpAnalyze(prolayer);
   }
   else if(protocol==0x06)
   {
       TcpAnalyze(prolayer);
   }
   else if(protocol==0x11)
   {
       UdpAnalyze(prolayer);
   }
}

void Interpret_Hanlder::IcmpAnalyze(QList<QStandardItem *> &prolayer)
{
    icmp_header* ih4=(icmp_header*)pkt_data;
    QStandardItem* icmp=new QStandardItem("ICMP");
    quint8 type=ih4->type;
    QStandardItem* typeti=new QStandardItem("类型: "+QString::number(type));
    QStandardItem* code=new QStandardItem("代码: "+QString::number(ih4->sum));
    QStandardItem* sum=new QStandardItem("校验和: 0x"+QString::number(qFromBigEndian(ih4->sum),16));
    pkt_data+=4;
    lpacket-=4;
    if(type==3||type==5||type==11)
    {
        icmp_un* iun=(icmp_un*) pkt_data;
        QStandardItem* unuse=new QStandardItem("未使用: "+QString::number(qFromBigEndian(iun->unuse),16));
        pkt_data+=4;
        lpacket-=4;
        QList<QStandardItem *> elselayer;
        IPv4Analyze(elselayer);
        icmp->appendRows(QList<QStandardItem*>()<<typeti<<code<<sum<<unuse<<elselayer);
        prolayer.append(icmp);
    }
    else if(type==8||type==0)
    {
        icmp_8w0* i8w0=(icmp_8w0*) pkt_data;
        QStandardItem* id=new QStandardItem("ID (BE): 0x"+QString::number(qFromBigEndian(i8w0->id),16));
        QStandardItem* seq=new QStandardItem("序列号 (BE): 0x"+QString::number(qFromBigEndian(i8w0->seq),16));
        lpacket-=4;
        QStandardItem* data=new QStandardItem("Data: "+QString::number(lpacket)+" bytes");
        icmp->appendRows(QList<QStandardItem*>()<<typeti<<code<<sum<<id<<seq<<data);
        prolayer.append(icmp);
    }
    else
    {
        icmp->appendRows(QList<QStandardItem*>()<<typeti<<code<<sum);
        prolayer.append(icmp);
    }
}

void Interpret_Hanlder::TcpAnalyze(QList<QStandardItem *> &prolayer)
{
    tcp_header* tcph=(tcp_header*)pkt_data;
    pkt_data+=(tcph->dtoff&0xf0)>>2;
    lpacket-=(tcph->dtoff&0xf0)>>2;
    QStandardItem* tcp=new QStandardItem("TCP");
    QStandardItem* srcport=new QStandardItem("源端口: "+QString::number(qFromBigEndian(tcph->srcport)));
    QStandardItem* desport=new QStandardItem("目的端口: "+QString::number(qFromBigEndian(tcph->desport)));
    QStandardItem* seq=new QStandardItem("序号: "+QString::number(qFromBigEndian(tcph->seq)));
    if(isICMP==true)
    {
        tcp->appendRows(QList<QStandardItem*>()<<srcport<<desport<<seq);
        return;
    }
    QStandardItem* ack=new QStandardItem("确认号: "+QString::number(qFromBigEndian(tcph->ack)));
    QStandardItem* hl=new QStandardItem("TCP报头长度: "+QString::number((tcph->dtoff&0xf0)>>2)+" bytes");
    QStandardItem* flags=new QStandardItem("标志位: 0x"+QString::number(((tcph->dtoff&0x0f)+tcph->flags),16));
    QStandardItem* win=new QStandardItem("窗口: "+QString::number(qFromBigEndian(tcph->win)));
    QStandardItem* sum=new QStandardItem("检验和: 0x"+QString::number(qFromBigEndian(tcph->sum),16));
    QStandardItem* upt=new QStandardItem("紧急指针: "+QString::number(qFromBigEndian(tcph->upt)));
    tcp->appendRows(QList<QStandardItem*>()<<srcport<<desport<<seq<<ack<<hl<<flags<<win<<sum<<upt);
    if(lpacket>0)
    {
        QStandardItem* data=new QStandardItem("TCP payload: "+QString::number(lpacket)+" bytes");
        tcp->appendRow(data);
    }
    prolayer.append(tcp);
}

void Interpret_Hanlder::UdpAnalyze(QList<QStandardItem *> &prolayer)
{
    udp_header* udph=(udp_header*)pkt_data;
    pkt_data+=8;
    lpacket-=8;
    quint16 lsrc=qFromBigEndian(udph->srcport);
    quint16 ldes=qFromBigEndian(udph->desport);
    QStandardItem* udp=new QStandardItem("UDP");
    QStandardItem* srcport=new QStandardItem("源端口: "+QString::number(lsrc));
    QStandardItem* desport=new QStandardItem("目的端口: "+QString::number(ldes));
    QStandardItem* len=new QStandardItem("长度: "+QString::number(qFromBigEndian(udph->len)));
    QStandardItem* sum=new QStandardItem("校验和: 0x"+QString::number(qFromBigEndian(udph->sum),16));
    if(isICMP==true)
    {
        udp->appendRows(QList<QStandardItem*>()<<srcport<<desport<<len<<sum);
        prolayer.append(udp);
        return;
    }
    else
    {
        if(lsrc==53||ldes==53)
        {
            udp->appendRows(QList<QStandardItem*>()<<srcport<<desport<<len<<sum);
            prolayer.append(udp);
            DnsAnalyze(prolayer);
        }
        else
        {
            QStandardItem* data=new QStandardItem("UDP payload: "+QString::number(lpacket)+" bytes");
            udp->appendRows(QList<QStandardItem*>()<<srcport<<desport<<len<<sum<<data);
            prolayer.append(udp);
        }
    }
}

void Interpret_Hanlder::DnsAnalyze(QList<QStandardItem *> &prolayer)
{
    dns_header* dnsh=(dns_header*)(pkt_data+8);
    pkt_data+=12;
    lpacket-=12;
    QStandardItem* dns=new QStandardItem("DNS");
    QStandardItem* id=new QStandardItem("事务ID: "+QString::number(qFromBigEndian(dnsh->id),16));
    QStandardItem* flags=new QStandardItem("标志: 0x"+QString::number(qFromBigEndian(dnsh->flags),16));
    QStandardItem* qst=new QStandardItem("问题数: "+QString::number(qFromBigEndian(dnsh->qst),16));
    QStandardItem* asr=new QStandardItem("回答数: "+QString::number(qFromBigEndian(dnsh->asr),16));
    QStandardItem* aut=new QStandardItem("授权数: "+QString::number(qFromBigEndian(dnsh->aut),16));
    QStandardItem* add=new QStandardItem("附加数: "+QString::number(qFromBigEndian(dnsh->add),16));
    QStandardItem* data=new QStandardItem("DNS payload: "+QString::number(lpacket)+" bytes");
    dns->appendRows(QList<QStandardItem*>()<<id<<flags<<qst<<asr<<aut<<add<<data);
    prolayer.append(dns);
}





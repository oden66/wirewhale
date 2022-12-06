#ifndef INTERPRET_HANLDER_H
#define INTERPRET_HANLDER_H

#define HAVE_REMOTE

#include <QObject>
#include <QtEndian>
#include <QDebug>
#include <QStandardItemModel>
#include "pcap.h"
#include "protocol_struct.h"

class Interpret_Hanlder : public QObject
{
    Q_OBJECT
public:
    explicit Interpret_Hanlder(QObject *parent = nullptr);
    QString IptoQStr(ip_address ip);
    QString HwtoQStr(quint8* hw);
    void PacketList(int count,QString time,struct pcap_pkthdr *header,const quint8 *pktdata);
    void ArpList(QStringList &list);
    void IcmpList(QStringList &list);
    void TcpList(QStringList &list);
    void UdpList(QStringList &list);
    void PacketAnalyze(quint32 length,const quint8 *pktdata);
    void ArpAnalyze(QList<QStandardItem*> &prolayer);
    void IPv4Analyze(QList<QStandardItem*> &prolayer);
    void IcmpAnalyze(QList<QStandardItem*> &prolayer);
    void TcpAnalyze(QList<QStandardItem*> &prolayer);
    void UdpAnalyze(QList<QStandardItem*> &prolayer);
    void DnsAnalyze(QList<QStandardItem*> &prolayer);
signals:
    void ListInfo(QStringList list);
    void AnalyzeSignal(QList<QStandardItem*> prolayer);
private:
    quint32 lpacket;
    const quint8 *pkt_data;
    bool isICMP;
};

#endif // INTERPRET_HANLDER_H

#include "capture_hanlder.h"

Capture_Hanlder::Capture_Hanlder(QObject *parent)
    : QObject{parent}
{
    ihanlder=new Interpret_Hanlder();
    adhandle=nullptr;
    pcap_if_name=nullptr;
    firstsec=0;
    firstusec=0;
    count=0;
}

void Capture_Hanlder::StartCapture(char *pcap_if_name)
{
    this->pcap_if_name=pcap_if_name;
    char errbuf[PCAP_ERRBUF_SIZE];
    int res;
    struct pcap_pkthdr *header;
    const quint8 *pkt_data;
    pcap_dumper_t *dumpfile;
    this->adhandle=pcap_open(pcap_if_name,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,NULL,errbuf);
    if(adhandle==NULL)
    {
        qDebug()<<"Unable to open the adapter,该设备不支持Winpcap";
        return;
    }
    QString filename=QDateTime::currentDateTime().toString("yyyy-MM-dd-HH-mm-ss")+".pcap";
    emit SendFileName(filename);
    dumpfile=pcap_dump_open(adhandle,filename.toStdString().c_str());
    while((res=pcap_next_ex(adhandle,&header,&pkt_data))>=0)
    {
        if(res==0)
        {
            continue;
        }
        if(count++==0)
        {
            firstsec=header->ts.tv_sec;
            firstusec=header->ts.tv_usec;
        }
        long sec=header->ts.tv_sec-firstsec;
        long usec=header->ts.tv_usec-firstusec;
        if(header->ts.tv_usec-firstusec<0)
        {
            sec-=1;
            usec+=1000000;
        }
        ihanlder->PacketList(count,QString::number(sec)+"."+QString("%1").arg(QString::number(usec),6,QChar('0')),header,pkt_data);
        pcap_dump((unsigned char *)dumpfile,header,pkt_data);
    }
    if(res==-1)
    {
        qDebug()<<pcap_geterr(adhandle);
    }
}

void Capture_Hanlder::FilterTraffic(quint32 netmask, QString filter)
{
    this->netmask=netmask;
    this->filter=filter;
    struct bpf_program fcode;
    if (pcap_compile(adhandle,&fcode,filter.toStdString().c_str(),1,netmask)<0)
    {
        qDebug()<<"无法编译数据包过滤器,检查语法";
        return;
    }
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        qDebug()<<"Error setting the filter";
        return;
    }
}

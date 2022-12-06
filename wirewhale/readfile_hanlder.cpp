#include "readfile_hanlder.h"

ReadFile_Hanlder::ReadFile_Hanlder(QObject *parent)
    : QObject{parent}
{
    fp=nullptr;
    rhanlder=new Interpret_Hanlder();
    firstsec=0;
    firstusec=0;
    count=0;
}


void ReadFile_Hanlder::ReadFile(QString filename)
{
    this->filename=filename;
    int res;
    struct pcap_pkthdr *header;
    const quint8 *pkt_data;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];
    if (pcap_createsrcstr(source,PCAP_SRC_FILE,NULL,NULL,filename.toStdString().c_str(),errbuf)!= 0)
    {
        qDebug()<<"Error creating a source string";
        return;
    }
    this->fp=pcap_open(source,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,NULL,errbuf);
    if(this->fp==NULL)
    {
        qDebug()<<"Unable to open the file";
        return;
    }
    while((res=pcap_next_ex(this->fp,&header,&pkt_data))>=0)
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
        rhanlder->PacketList(count,QString::number(sec)+"."+QString("%1").arg(QString::number(usec),6,QChar('0')),header,pkt_data);
        time.append(header->ts.tv_sec+header->ts.tv_usec);
    }
    if(res==-1)
    {
        qDebug()<<pcap_geterr(this->fp);
        return;
    }
}

void ReadFile_Hanlder::FilterTraffic(QString filter)
{
    int res;
    struct bpf_program fcode;
    struct pcap_pkthdr *header;
    const quint8 *pkt_data;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];
    if (pcap_createsrcstr(source,PCAP_SRC_FILE,NULL,NULL,filename.toStdString().c_str(),errbuf)!= 0)
    {
        qDebug()<<"Error creating a source string";
        return;
    }
    this->fp=pcap_open(source,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,NULL,errbuf);
    if(this->fp==NULL)
    {
        qDebug()<<"Unable to open the file";
        return;
    }
    if (pcap_compile(this->fp,&fcode,filter.toStdString().c_str(),1,0)<0)
    {
        qDebug()<<"无法编译数据包过滤器,检查语法";
        return;
    }
    if (pcap_setfilter(this->fp, &fcode) < 0)
    {
        qDebug()<<"Error setting the filter";
        return;
    }
    while((res=pcap_next_ex(this->fp,&header,&pkt_data))>=0)
    {
        if(res==0)
        {
            continue;
        }
        long stime=header->ts.tv_sec+header->ts.tv_usec;
        long sec=header->ts.tv_sec-firstsec;
        long usec=header->ts.tv_usec-firstusec;
        if(header->ts.tv_usec-firstusec<0)
        {
            sec-=1;
            usec+=1000000;
        }
        rhanlder->PacketList(time.indexOf(stime)+1,QString::number(sec)+"."+QString("%1").arg(QString::number(usec),6,QChar('0')),header,pkt_data);
    }
    if(res==-1)
    {
        qDebug()<<pcap_geterr(this->fp);
        return;
    }
}

void ReadFile_Hanlder::AnalyzePacket(int row)
{
    int res;
    struct pcap_pkthdr *header;
    const quint8 *pkt_data;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];
    if (pcap_createsrcstr(source,PCAP_SRC_FILE,NULL,NULL,filename.toStdString().c_str(),errbuf)!= 0)
    {
        qDebug()<<"Error creating a source string";
        return;
    }
    this->fp=pcap_open(source,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,NULL,errbuf);
    if(this->fp==NULL)
    {
        qDebug()<<"Unable to open the file";
        return;
    }
    int i=1;
    while((res=pcap_next_ex(this->fp,&header,&pkt_data))>=0&&i<row)
    {
        if(res==0)
        {
            continue;
        }
        i++;
    }
    const quint8 * byte=pkt_data;
    QList<QString> bytes;
    quint32 sum=0;
    rhanlder->PacketAnalyze(header->len,pkt_data);
    while(sum<header->len)
    {
        QString row;
        for(int j=0;j<2;j++)
        {
            int k=8;
            while(k>0&&sum<header->len)
            {
                QString num=QString::number(*byte,16);
                if((*byte)<10)
                {
                    row+="0"+num+"  ";
                }
                else
                {
                   row+=num+"  ";
                }
                byte++;
                k--;
                sum++;
            }
            row+="  ";
        }
        bytes<<row;
    }
    emit SendBytesSignal(bytes);
    if(res==-1)
    {
        qDebug()<<pcap_geterr(this->fp);
        return;
    }
}

#ifndef READFILE_HANLDER_H
#define READFILE_HANLDER_H

#define HAVE_REMOTE

#include <QObject>
#include <QDebug>
#include "pcap.h"
#include "interpret_hanlder.h"

class ReadFile_Hanlder : public QObject
{
    Q_OBJECT
public:
    explicit ReadFile_Hanlder(QObject *parent = nullptr);
    void ReadFile(QString filename);
    void FilterTraffic(QString filter);
    void AnalyzePacket(int row);
    Interpret_Hanlder* rhanlder;
signals:
    void SendBytesSignal(QList<QString> bytes);
private:
    pcap_t *fp;
    QString filename;
    QList<long> time;
    long firstsec;
    long firstusec;
    int count;
};

#endif // READFILE_HANLDER_H

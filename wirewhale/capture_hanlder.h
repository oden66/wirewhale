#ifndef CAPTURE_HANLDER_H
#define CAPTURE_HANLDER_H

#define HAVE_REMOTE

#include <QObject>
#include <QDebug>
#include <QDateTime>
#include "pcap.h"
#include "interpret_hanlder.h"

class Capture_Hanlder : public QObject
{
    Q_OBJECT
public:
    explicit Capture_Hanlder(QObject *parent = nullptr);
    void StartCapture(char* pcap_if_name);
    void FilterTraffic(quint32 netmask,QString filter);
    Interpret_Hanlder* ihanlder;
private:
    char *pcap_if_name;
    pcap_t *adhandle;
    quint32 netmask;
    QString filter;
    long firstsec;
    long firstusec;
    int count;
signals:
    void SendFileName(QString filename);
};
#endif // CAPTURE_HANLDER_H

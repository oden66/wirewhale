#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#define HAVE_REMOTE

#include <QMainWindow>
#include <QMessageBox>
#include <QScrollBar>
#include <QThread>
#include <QDateTime>
#include <QFileDialog>
#include <QFileInfo>

#include "pcap.h"
#include "capture_hanlder.h"
#include "readfile_hanlder.h"
#include "interpret_hanlder.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void Init();
    void DeleteCapture();
    void DeleteReadfile();
    void GetDeviceList();
    pcap_if_t* GetSelectAdapter();
    void GetPacketSn(int row);
    void SendFilterParam();
    void StartCapture();
    void StopCapture();
    void RestartCapture();
    void ShowList(QStringList list);
    void ShowBytes(QList<QString> bytes);
    void GetFileName(QString filename);
    void OpenFile();
    void ReadFile();
    void AnalyzeShow(QList<QStandardItem*> prolayer);
signals:
    void CaptureStartSignal(char* pcap_if_name);
    void FileReadSignal(QString filename);
    void OpenSignal(QString filename);
    void FilterSignal(QString filter);
    void CaptureFilterSignal(quint32 netmask,QString filter);
    void SendPacketSn(int sn);
private:
    Ui::MainWindow *ui;
    pcap_if_t *alldevs;
    Capture_Hanlder* capture_hanlder;
    ReadFile_Hanlder* readfile_hanlder;
    QThread* capture_thread;
    QThread* readfile_thread;
    char* pcap_if_name;
    QString filename;
};
#endif // MAINWINDOW_H

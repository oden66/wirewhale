#include "mainwindow.h"
#include "ui_mainwindow.h"


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    alldevs=nullptr;
    capture_hanlder=nullptr;
    readfile_hanlder=nullptr;
    readfile_hanlder=nullptr;
    capture_thread=nullptr;
    pcap_if_name=nullptr;
    this->Init();
    this->GetDeviceList();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::Init()
{
    ui->actionCaptureRestart->setEnabled(false);
    ui->actionCaptureStop->setEnabled(false);
    ui->packetList->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    ui->packetList->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    ui->packetList->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    ui->packetList->verticalScrollBar()->setSingleStep(1);
    ui->packetList->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->packetList->setSelectionBehavior(QTableWidget::SelectRows);
    ui->packetDetails->setEditTriggers(QTreeView::NoEditTriggers);
    connect(ui->actionCaptureStart,&QAction::triggered,this,&MainWindow::StartCapture);
    connect(ui->actionCaptureStop,&QAction::triggered,this,&MainWindow::StopCapture);
    connect(ui->actionCaptureRestart,&QAction::triggered,this,&MainWindow::RestartCapture);
    connect(ui->actionFileOpen,&QAction::triggered,this,&MainWindow::OpenFile);
    connect(ui->filterLineEdit,&QLineEdit::returnPressed,this,&MainWindow::SendFilterParam);
    connect(ui->packetList,&QTableWidget::cellPressed,this,&MainWindow::GetPacketSn);
}

void MainWindow::DeleteCapture()
{
    disconnect(this,&MainWindow::CaptureStartSignal,capture_hanlder,&Capture_Hanlder::StartCapture);
    if(capture_thread->isRunning()==true)
    {
        capture_thread->terminate();
    }
    delete capture_thread;
    delete capture_hanlder;
    capture_hanlder=nullptr;
    capture_thread=nullptr;
}

void MainWindow::DeleteReadfile()
{
    disconnect(this,&MainWindow::OpenSignal,readfile_hanlder,&ReadFile_Hanlder::ReadFile);
    disconnect(this,&MainWindow::FilterSignal,readfile_hanlder,&ReadFile_Hanlder::FilterTraffic);
    disconnect(this,&MainWindow::FilterSignal,readfile_hanlder,&ReadFile_Hanlder::FilterTraffic);
    disconnect(readfile_hanlder->rhanlder,&Interpret_Hanlder::ListInfo,this,&MainWindow::ShowList);
    disconnect(readfile_hanlder,&ReadFile_Hanlder::SendBytesSignal,this,&MainWindow::ShowBytes);
    if(readfile_thread->isRunning()==true)
    {
        readfile_thread->terminate();
    }
    delete readfile_thread;
    delete readfile_hanlder;
    readfile_hanlder=nullptr;
    readfile_thread=nullptr;
}

void MainWindow::GetDeviceList()
{
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING,NULL,&alldevs, errbuf) == -1)
    {
        qDebug() << errbuf;
    }
    for(d = alldevs;d;d=d->next)
    {
        ui->deviceListComboBox->addItem(d->description);
    }
}

pcap_if_t* MainWindow::GetSelectAdapter()
{
    int i=ui->deviceListComboBox->currentIndex();
    pcap_if_t *d=nullptr;
    for(d=alldevs;i>0;i--,d=d->next);
    return d;
}

void MainWindow::GetPacketSn(int row)
{
   QTableWidgetItem* snItem=ui->packetList->item(row,0);
   emit SendPacketSn(snItem->text().toInt());
}

void MainWindow::SendFilterParam()
{
    if(capture_thread!=nullptr)
    {
        pcap_if_t *d=GetSelectAdapter();
        quint32 netmask=0xffffff;
        if(d->addresses!=nullptr)
        {
            netmask=((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
        }
        QString filter=ui->filterLineEdit->text();
        emit CaptureFilterSignal(netmask,filter);
    }
    else if(readfile_thread!=nullptr)
    {
        ui->packetList->clearContents();
        ui->packetList->setRowCount(0);
        QString filter=ui->filterLineEdit->text();
        emit FilterSignal(filter);
    }
    else if(ui->packetList->rowCount()!=0)
    {
        ui->packetList->clearContents();
        ui->packetList->setRowCount(0);
        readfile_thread=new QThread;
        readfile_hanlder=new ReadFile_Hanlder;
        connect(this,&MainWindow::FileReadSignal,readfile_hanlder,&ReadFile_Hanlder::ReadFile);
        connect(this,&MainWindow::FilterSignal,readfile_hanlder,&ReadFile_Hanlder::FilterTraffic);
        readfile_hanlder->moveToThread(readfile_thread);
        readfile_thread->start();
        emit FileReadSignal(filename);
        connect(readfile_hanlder->rhanlder,&Interpret_Hanlder::ListInfo,this,&MainWindow::ShowList);
        QString filter=ui->filterLineEdit->text();
        emit FilterSignal(filter);
    }
}

void MainWindow::StartCapture()
{
    ui->packetList->clearContents();
    ui->packetList->setRowCount(0);
    if(readfile_hanlder!=nullptr)
    {
        DeleteReadfile();
    }
    ui->actionCaptureRestart->setEnabled(true);
    ui->actionCaptureStop->setEnabled(true);
    ui->actionFileOpen->setEnabled(false);
    ui->actionCaptureStart->setEnabled(false);
    ui->actionCaptureStart->setChecked(false);
    capture_thread=new QThread;
    capture_hanlder=new Capture_Hanlder;
    connect(this,&MainWindow::CaptureStartSignal,capture_hanlder,&Capture_Hanlder::StartCapture);
    connect(this,&MainWindow::CaptureFilterSignal,capture_hanlder,&Capture_Hanlder::FilterTraffic,Qt::DirectConnection);
    connect(capture_hanlder->ihanlder,&Interpret_Hanlder::ListInfo,this,&MainWindow::ShowList);
    connect(capture_hanlder,&Capture_Hanlder::SendFileName,this,&MainWindow::GetFileName);
    capture_hanlder->moveToThread(capture_thread);
    capture_thread->start();
    pcap_if_t *d=GetSelectAdapter();
    pcap_if_name=d->name;
    emit CaptureStartSignal(pcap_if_name);
}

void MainWindow::StopCapture()
{
    this->DeleteCapture();
    ui->actionCaptureStart->setEnabled(true);
    ui->actionCaptureRestart->setEnabled(false);
    ui->actionCaptureStop->setEnabled(false);
    ui->actionFileOpen->setEnabled(true);
    ReadFile();
}

void MainWindow::RestartCapture()
{
    ui->packetList->clearContents();
    ui->packetList->setRowCount(0);
    this->StopCapture();
    this->StartCapture();
}

void MainWindow::ShowList(QStringList list)
{
    int rowcount=ui->packetList->rowCount();
    ui->packetList->insertRow(rowcount);
    int i=0;
    for(auto &&item:list)
    {
        QTableWidgetItem* itm = new QTableWidgetItem(item);
        ui->packetList->setItem(rowcount,i++,itm);
    }
    ui->packetList->scrollToBottom();
}

void MainWindow::ShowBytes(QList<QString> bytes)
{
    ui->packetBytes->clear();
    for(auto str:bytes)
    {
        ui->packetBytes->appendPlainText(str);
    }
}

void MainWindow::GetFileName(QString filename)
{
    this->filename=filename;
}

void MainWindow::OpenFile()
{
    QString filepath=QFileDialog::getOpenFileName(NULL,tr("打开文件"),QDir::currentPath());
    if(filepath!="")
    {
        QFileInfo fileinfo=QFileInfo(filepath);
        this->filename=fileinfo.fileName();
        ReadFile();
    }
}

void MainWindow::ReadFile()
{
    if(readfile_hanlder!=nullptr)
    {
        DeleteReadfile();
    }
    if(capture_hanlder!=nullptr)
    {
        DeleteCapture();
    }
    ui->packetList->clearContents();
    ui->packetList->setRowCount(0);
    readfile_thread=new QThread;
    readfile_hanlder=new ReadFile_Hanlder;
    connect(this,&MainWindow::FileReadSignal,readfile_hanlder,&ReadFile_Hanlder::ReadFile);
    connect(this,&MainWindow::FilterSignal,readfile_hanlder,&ReadFile_Hanlder::FilterTraffic);
    connect(this,&MainWindow::SendPacketSn,readfile_hanlder,&ReadFile_Hanlder::AnalyzePacket);
    connect(readfile_hanlder->rhanlder,&Interpret_Hanlder::AnalyzeSignal,this,&MainWindow::AnalyzeShow);
    connect(readfile_hanlder->rhanlder,&Interpret_Hanlder::ListInfo,this,&MainWindow::ShowList);
    connect(readfile_hanlder,&ReadFile_Hanlder::SendBytesSignal,this,&MainWindow::ShowBytes);
    readfile_hanlder->moveToThread(readfile_thread);
    readfile_thread->start();
    emit FileReadSignal(filename);
}

void MainWindow::AnalyzeShow(QList<QStandardItem *> prolayer)
{
    QStandardItemModel* model=new QStandardItemModel(ui->packetDetails);
    ui->packetDetails->setModel(model);
    for(auto item:prolayer)
    {
        model->appendRow(item);
    }
}



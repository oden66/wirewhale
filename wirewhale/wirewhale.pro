QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    capture_hanlder.cpp \
    interpret_hanlder.cpp \
    main.cpp \
    mainwindow.cpp \
    readfile_hanlder.cpp

HEADERS += \
    capture_hanlder.h \
    interpret_hanlder.h \
    mainwindow.h \
    protocol_struct.h \
    readfile_hanlder.h

FORMS += \
    mainwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    resource.qrc

INCLUDEPATH += \
    ../Include
LIBS += \
    -L $$PWD/../Lib/x64 -lwpcap

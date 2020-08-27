#-------------------------------------------------
#
# Project created by QtCreator 2020-07-30T01:53:58.062Z
#
#-------------------------------------------------

QT       += widgets

QT       -= gui

TARGET = Encryption
TEMPLATE = lib

DEFINES += ENCRYPTION_LIBRARY

CONFIG += c++11 plugin
CONFIG -= debug_and_release_target

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES +=         encryption.cpp \
    cipher.cpp

HEADERS +=         encryption.h \
    cipher.h

FORMS +=        encryption.ui

DISTFILES +=     

RESOURCES += 

INCLUDEPATH += $$PWD/../../../hobbits-core
DEPENDPATH += $$PWD/../../../hobbits-core

LIBS += -L$$OUT_PWD/../../../hobbits-core/ -lhobbits-core

INCLUDEPATH += ../../../../Nabeela/Sources/openssl-3.0.0-alpha6/include

LIBS += -L../../../../Nabeela/Sources/openssl-3.0.0-alpha6/libcrypto.a -lcrypto
LIBS += -L../../../../Nabeela/Sources/openssl-3.0.0-alpha6/libssl.a -lssl

unix:!mac {
    QMAKE_LFLAGS_RPATH=
    QMAKE_LFLAGS += "-Wl,-rpath,'$$ORIGIN/../../lib:$$ORIGIN'"
}

mac {
    QMAKE_LFLAGS_RPATH=
    QMAKE_LFLAGS += "-Wl,-rpath,'@executable_path/../Frameworks'"
}

unix {
    target.path = target.path = $$(HOME)/.local/share/hobbits/plugins/operators
    INSTALLS += target
}


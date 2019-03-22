   
#your Ida SDK location either relative to msp430emu
#or absolute
SDK = ../..

OBJECTS_DIR = p64-7

#Need to change the following to your Ida install location
linux-g++:IDA_APP = /opt/ida-$$(IDA_VERSION)
macx:IDA_APP = "/Applications/IDA\ Pro\ $$(IDA_VERSION)/ida64.app/Contents"

#Need to change the following to your Qt install location
macx: {
   greaterThan(QT_MAJOR_VERSION, 4):QT_LOC = /Users/qt-5.4.1/5.4/clang_64/lib
   lessThan(QT_MAJOR_VERSION, 5):QT_LOC = /usr/local/qt/lib
   QT_TAIL = .framework/Versions/$$QT_MAJOR_VERSION/Headers
   #create our own list of Qt modules
   MODS = QtGui QtCore
   greaterThan(QT_MAJOR_VERSION, 4):MODS += QtWidgets
}

defineReplace(makeIncludes) {
   variable = $$1
   modules = $$eval($$variable)
   dirs =
   for(module, modules) {
      dir = $${QT_LOC}/$${module}$${QT_TAIL}
      dirs += $$dir
   }
   return($$dirs)
}

TEMPLATE = lib

greaterThan(QT_MAJOR_VERSION, 4):QT += widgets

CONFIG += qt dll

INCLUDEPATH += $${SDK}/include

DESTDIR = bin

DEFINES += __IDP__ __QT__ __EA64__ __X64__
win32:DEFINES += __NT__ WIN32
win32:DEFINES -= UNICODE
win32:DEFINES += _CRT_SECURE_NO_WARNINGS
win32:QMAKE_TARGET.arch = x86_64
linux-g++:DEFINES += __LINUX__
macx:DEFINES += __MAC__

win32:LIBS += comdlg32.lib gdi32.lib user32.lib advapi32.lib ida.lib
win32-msvc2013: {
   exists( $${SDK}/lib/vc.w64/ida.lib ) {
      LIBS += -L$${SDK}/lib/vc.w64
   } else {
      LIBS += -L$${SDK}/lib/x64_win_vc_64
      LIBS += -L$${SDK}/lib/x64_win_qt
   }
   QMAKE_LFLAGS_RPATH =
   QMAKE_LIBDIR_QT =
}
linux-g++:LIBS += -L$${IDA_APP} -lida64
macx:LIBS += -L$${IDA_APP}/MacOs -lida64

#don't let qmake force search any libs other than the
#ones that ship with Ida
linux-g++:QMAKE_LFLAGS_RPATH =
linux-g++:QMAKE_LIBDIR_QT =

macx:QMAKE_INCDIR = $$makeIncludes(MODS)
#add QTs actual include file location this way since -F is not
#handled by QMAKE_INCDIR
macx:QMAKE_CXXFLAGS += -m64 -F$${QT_LOC}

linux-g++:QMAKE_CXXFLAGS = -m64

linux-g++|macx: {
   QMAKE_CXXFLAGS += -m64
   QMAKE_CFLAGS += -m64
   QMAKE_LFLAGS += -m64
}

macx:QMAKE_LFLAGS += -F$${IDA_APP}/Frameworks
macx:QMAKE_LIBDIR_QT =

SOURCES = msp430emu.cpp \
   msp430emu_ui_qt.cpp \
	cpu.cpp \
	break.cpp \
	buffer.cpp \
	emu_script.cpp

HEADERS = break.h \
   buffer.h \
   cpu.h \
   emu_script.h \
   sdk_versions.h \
   msp430emu_ui_qt.h \
   msp430defs.h

win32:TARGET_EXT=.dll
linux-g++:TARGET_EXT=.so
macx:TARGET_EXT=.dylib

TARGET = msp430emu_qt64


#your Ida SDK location either relative to msp430emu
#or absolute
SDK = ../..

OBJECTS_DIR = p32

#Need to change the following to your Ida install location
win32:IDA_APP = "C:/Program Files (x86)/Ida"
linux-g++:IDA_APP = /opt/ida-$$(IDA_VERSION)
macx:IDA_APP = "/Applications/IDA\ Pro\ $$(IDA_VERSION)/idaq.app/Contents

#Need to change the following to your Qt install location
macx:QT_LOC = /usr/local/qt/lib
macx:QT_TAIL = .framework/Versions/4/Headers
#create our own list of Qt modules
macx:MODS = QtGui QtCore

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

#QT +=

CONFIG += qt dll

INCLUDEPATH += $${SDK}/include

DESTDIR = $${SDK}/bin/plugins

#DEFINES += DEBUG
DEFINES += __IDP__ __QT__
win32:DEFINES += __NT__ WIN32
win32:DEFINES -= UNICODE
win32:DEFINES += _CRT_SECURE_NO_WARNINGS
linux-g++:DEFINES += __LINUX__
macx:DEFINES += __MAC__

win32:LIBS += comdlg32.lib gdi32.lib user32.lib advapi32.lib ida.lib
win32-msvc2008: {
   exists( $${SDK}/lib/vc.w32/ida.lib ) {
      LIBS += -L$${SDK}/lib/vc.w32
   } else {
      LIBS += -L$${SDK}/lib/x86_win_vc_32
   }
}
linux-g++:LIBS += -L$${IDA_APP} -lida
macx:LIBS += -L$${IDA_APP}/MacOs -lida

#don't let qmake force search any libs other than the
#ones that ship with Ida
linux-g++:QMAKE_LFLAGS_RPATH =
linux-g++:QMAKE_LIBDIR_QT =

macx:QMAKE_INCDIR = $$makeIncludes(MODS)
#add QTs actual include file location this way since -F is not
#handled by QMAKE_INCDIR
macx:QMAKE_CXXFLAGS += -m32 -F$${QT_LOC}

linux-g++:QMAKE_CXXFLAGS = -m32

linux-g++|macx: {
   QMAKE_CXXFLAGS += -m32
   QMAKE_CFLAGS += -m32
   QMAKE_LFLAGS += -m32
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

win32:TARGET_EXT=.plw
linux-g++:TARGET_EXT=.plx
macx:TARGET_EXT=.pmc

TARGET = msp430emu_qt

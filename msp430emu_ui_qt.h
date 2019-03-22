/*
   Source for MSP430 emulator IdaPro plugin
   Copyright (c) 2014 Chris Eagle
   
   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the Free
   Software Foundation; either version 2 of the License, or (at your option) 
   any later version.
   
   This program is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
   FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for 
   more details.
   
   You should have received a copy of the GNU General Public License along with 
   this program; if not, write to the Free Software Foundation, Inc., 59 Temple 
   Place, Suite 330, Boston, MA 02111-1307 USA
*/

#ifndef __MSP430EMU_QT_H__
#define __MSP430EMU_QT_H__

#ifdef __QT__
#ifndef QT_NAMESPACE
#define QT_NAMESPACE QT
#endif
#endif

#include <QtGui>
#include <QDialog>
#include <QListWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QMainWindow>
#include <QRadioButton>
#include <QValidator>
#include <QSpinBox>
#include <QPushButton>
#include <QCheckBox>
#include <QAction>

#include "msp430defs.h"
#include "msp430emu_ui.h"

using namespace QT;

class AllIntValidator : public QValidator {
   Q_OBJECT
public:
   AllIntValidator(QObject *parent = 0) : QValidator(parent) {}
   State validate(QString &input, int &pos) const;
};

class MSP430Dialog : public QMainWindow {
   Q_OBJECT
public:
   MSP430Dialog(QWidget *parent = 0);
public slots:
   void changePC();
   void changeSP();
   void changeSR();
   void changeCG();
   void changeR4();
   void changeR5();
   void changeR6();
   void changeR7();
   void changeR8();
   void changeR9();
   void changeR10();
   void changeR11();
   void changeR12();
   void changeR13();
   void changeR14();
   void changeR15();
   void dumpRange();
   void reset();
   void breakOnSyscalls();
   void microCorruptionBugs();
   void trackExec();
   void traceExec();
   void setBreak();
   void clearBreak();
   void hideEmu();
   void step();
   void skip();
   void run();
   void doBreak();
   void runCursor();
   void jumpCursor();
   void pushData();
   void setMemory();
   
public:
   QLineEdit *QPC;
   QLineEdit *QSP;
   QLineEdit *QSR;
   QLineEdit *QCG;
   QLineEdit *QR4;
   QLineEdit *QR5;
   QLineEdit *QR6;
   QLineEdit *QR7;
   QLineEdit *QR8;
   QLineEdit *QR9;
   QLineEdit *QR10;
   QLineEdit *QR11;
   QLineEdit *QR12;
   QLineEdit *QR13;
   QLineEdit *QR14;
   QLineEdit *QR15;
private:
   QAction *emulateTrack_fetched_bytesAction;
   QAction *emulateTrace_executionAction;
   QAction *emulateMicrocorruptionBugModeAction;
   QAction *emulateBreakOnSyscallsAction;
   QPushButton *BREAK;
};

class SetMemoryDialog : public QDialog {
   Q_OBJECT
public:
   SetMemoryDialog(QWidget *parent = 0);
   QRadioButton *type_dword;
   QRadioButton *type_word;
   QRadioButton *type_byte;
   QRadioButton *type_ascii;
   QRadioButton *type_asciiz;
   QRadioButton *type_file;
   QLineEdit *mem_start;
   QLineEdit *mem_values;

private slots:
   void do_ok();
};

class CustomInputDialog : public QDialog {
   Q_OBJECT
public:
   CustomInputDialog(const char *console, unsigned int max, QWidget *parent = 0);
   QCheckBox *hex_or_not;
   QLineEdit *inputText;

   bytevec_t data;
private:
   unsigned int _max;

private slots:
   void do_ok();
};

#endif

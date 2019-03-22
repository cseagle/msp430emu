/*
   Source for MSP430 emulator IdaPro plugin
   Copyright (c) 2014 Chris Eagle
   
   This program is free software; you can rR4stribute it and/or modify it
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

/*
 *  This is the MSP430 Emulation plugin module
 *
 *  It is known to compile with
 *
 *  - Qt Version: Windows - Visual Studio 2008, Linux/OS X - g++
 *  - Windows only version (IDA < 6.0): Visual C++ 6.0, Visual Studio 2005, MinGW g++/make
 *
 */

#ifdef PACKED
#undef PACKED
#endif

#ifdef __QT__
#ifndef QT_NAMESPACE
#define QT_NAMESPACE QT
#endif
#endif

#include <QtGlobal>
#if QT_VERSION >= 0x050000
#define toAscii toLatin1
#endif

#include <QApplication>
#include <QMessageBox>
#include <QToolBar>
#include <QButtonGroup>
#include <QFileDialog>
#include <QInputDialog>
#include <QVBoxLayout>
#include <QLabel>
#include <QGroupBox>
#include <QFormLayout>
#include <QMenu>
#include <QCheckBox>
#include <QPlainTextEdit>
 
#include "msp430emu_ui_qt.h"

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <auto.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <nalt.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <struct.hpp>
#include <ctype.h>

#include "cpu.h"

QWidget *mainWindow;
MSP430Dialog *msp430Dlg;

QValidator::State AllIntValidator::validate(QString &input, int & /*pos*/) const {
   char *endptr;
   char *nptr = input.toAscii().data();
   if (*nptr == 0 || stricmp("0x", nptr) == 0) {
      return Intermediate;
   }
   strtoul(nptr, &endptr, 0);
   if (*nptr && !*endptr) {
      return Acceptable;
   }
   return Invalid;
}

AllIntValidator aiv;

//QFont fixed;

QWidget *getWidgetParent() {
   if (mainWindow == NULL) {
      mainWindow = QApplication::activeWindow();
   }
   return mainWindow;
}

/*
 * Set the title of the emulator window
 */
void setEmulatorTitle(const char *title) {
   msp430Dlg->setWindowTitle(title);
}

//convert a register number into a control ID for the register's display
QLineEdit *regToControl(unsigned int reg) {
   switch (reg) {
      case PC:
         return msp430Dlg->QPC;
      case SP:
         return msp430Dlg->QSP;
      case SR:
         return msp430Dlg->QSR;
      case CG:
         return msp430Dlg->QCG;
      case R4:
         return msp430Dlg->QR4;
      case R5:
         return msp430Dlg->QR5;
      case R6:
         return msp430Dlg->QR6;
      case R7:
         return msp430Dlg->QR7;
      case R8:
         return msp430Dlg->QR8;
      case R9:
         return msp430Dlg->QR9;
      case R10:
         return msp430Dlg->QR10;
      case R11:
         return msp430Dlg->QR11;
      case R12:
         return msp430Dlg->QR12;
      case R13:
         return msp430Dlg->QR13;
      case R14:
         return msp430Dlg->QR14;
      case R15:
         return msp430Dlg->QR15;
   }
   return NULL;
}

//update the specified register display with the specified 
//value. Useful for updating register contents based on user
//input
void updateRegisterDisplay(int r) {
   static bool registersSet[MAX_REG + 1];
   static unsigned int current[MAX_REG + 1];
   QLineEdit *l = regToControl(r);
   if (l) {
      char buf[16];
      unsigned int rval = getRegisterValue(r);
      ::qsnprintf(buf, sizeof(buf), "0x%04X", rval & 0xffff);
      QString v(buf);
      if (registersSet[r]) {
         if (rval != current[r]) {
            current[r] = rval;
            l->setStyleSheet("QLineEdit{color: red;}");
         }
         else {
            l->setStyleSheet("QLineEdit{color: black;}");
         }
      }
      else {
         registersSet[r] = true;
         current[r] = rval;
      }
      l->setText(v);
   }
}

//get an int value from Edit box string
//assumes value is a valid hex string
unsigned int getEditBoxInt(QLineEdit *l) {
   return strtoul(l->text().toAscii().data(), NULL, 0);
}

//display a single line input box with the given title, prompt
//and initial data value.  If the user does not cancel, their
//data is placed into the global variable "value"
char *inputBox(const char *boxTitle, const char *msg, const char *init) {
   static char value[80]; //value entered by the user
   bool ok;
   QString text = QInputDialog::getText(getWidgetParent(), boxTitle,
                              msg, QLineEdit::Normal, init, &ok);
   if (ok && !text.isEmpty()) {
      ::qstrncpy(value, text.toAscii().data(), sizeof(value));
      return value;
   }
   return NULL;
}

//display a single line input box with the given title, prompt
//and initial data value.  If the user does not cancel, their
//data is placed into the global variable "value"
bool do_getsn(bytevec_t &bv, unsigned int max, const char *console) {
   CustomInputDialog id(console, max, getWidgetParent());
   restoreCursor();
   int rc = id.exec();
   showWaitCursor();
   if (rc == QDialog::Accepted) {
      bv = id.data;
      return true;
   }
   return false;
}

char *getSaveFileName(const char *title, char *fileName, int nameSize, const char *filter) {
   if (fileName == NULL || nameSize == 0) {
      return NULL;
   }
   QString f = QFileDialog::getSaveFileName(getWidgetParent(), title,
                                            QString(), filter);
   if (!f.isNull()) {
      ::qstrncpy(fileName, f.toAscii().data(), nameSize);
      return fileName;
   }
   return NULL;
}

char *getDirectoryName(const char *title, char *dirName, int nameSize) {
   if (dirName == NULL || nameSize == 0) {
      return NULL;
   }

   QString dir = QFileDialog::getExistingDirectory(getWidgetParent(), title,
                                                 QString(), QFileDialog::ShowDirsOnly
                                                 | QFileDialog::DontResolveSymlinks);   
   
   if (!dir.isNull()) {
      ::qstrncpy(dirName, dir.toAscii().data(), nameSize);
      return dirName;
   }
   return NULL;
}

void showErrorMessage(const char *msg) {
   QMessageBox::warning(getWidgetParent(), "Error", msg);
}

//ask user for an file name and load the file into memory
//at the specified address
char *getOpenFileName(const char *title, char *fileName, int nameLen, const char *filter, char *initDir) {
   if (fileName == NULL || nameLen == 0) {
      return NULL;
   }
   QString f = QFileDialog::getOpenFileName(getWidgetParent(), title,
                                            initDir, filter);
   if (!f.isNull()) {
      ::qstrncpy(fileName, f.toAscii().data(), nameLen);
      return fileName;
   }
   return NULL;
}

static void setMemValues(unsigned int addr, char *v, unsigned int sz) {
   char *ptr;
   while ((ptr = strchr(v, ' ')) != NULL) {
      *ptr++ = 0;
      if (strlen(v)) {
         writeMem(addr, strtoul(v, NULL, 16), sz);
         addr += sz;
      }
      v = ptr;
   }
   if (strlen(v)) {
      writeMem(addr, strtoul(v, NULL, 16), sz);
   }
}

void SetMemoryDialog::do_ok() {
   char *ea = mem_start->text().toAscii().data();
   unsigned int addr = strtoul(ea, 0, 0);
   char *v = mem_values->text().toAscii().data();

   if (type_file->isChecked()) {
      memLoadFile(addr);
   }
   else if (type_byte->isChecked()) {
      setMemValues(addr, v, SIZE_BYTE);
   }
   else if (type_word->isChecked()) {
      setMemValues(addr, v, SIZE_WORD);
   }
   else if (type_ascii->isChecked() || type_asciiz->isChecked()) {
      while (*v) writeMem(addr++, *v++, SIZE_BYTE);
      if (type_asciiz->isChecked()) writeMem(addr, 0, SIZE_BYTE);
   }
   accept();
}

SetMemoryDialog::SetMemoryDialog(QWidget *parent) : QDialog(parent) {
   setSizeGripEnabled(false);
   setModal(true);

   QLabel *address = new QLabel("Start address:");
   QLabel *values = new QLabel("Space separated values:");

   QPushButton *set_ok = new QPushButton("&OK");
   set_ok->setAutoDefault(true);
   set_ok->setDefault(true);
   
   QPushButton *set_cancel = new QPushButton("&Cancel");
   set_cancel->setAutoDefault(true);
   
   QHBoxLayout *buttonLayout = new QHBoxLayout();
   buttonLayout->setSpacing(2);
   buttonLayout->setContentsMargins(4, 4, 4, 4);
   buttonLayout->addStretch(1);
   buttonLayout->addWidget(set_ok);
   buttonLayout->addWidget(set_cancel);
   buttonLayout->addStretch(1);
   
   QWidget *buttonPanel = new QWidget();
   buttonPanel->setLayout(buttonLayout);
   
   type_dword = new QRadioButton("32 bit hex");
   type_word = new QRadioButton("16 bit hex");
   type_byte = new QRadioButton("8 bit hex");
   type_ascii = new QRadioButton("ASCII w/o null");
   type_asciiz = new QRadioButton("ASCII w/ null");
   type_file = new QRadioButton("Load from file");   
   
   QGridLayout *gl = new QGridLayout();
   gl->setSpacing(2);
   gl->setContentsMargins(4, 4, 4, 4);
   
   gl->addWidget(type_byte, 0, 0);
   gl->addWidget(type_ascii, 0, 1);
   gl->addWidget(type_word, 1, 0);
   gl->addWidget(type_asciiz, 1, 1);
   gl->addWidget(type_dword, 2, 0);
   gl->addWidget(type_file, 2, 1);
   
   QGroupBox *groupBox = new QGroupBox("Data type");
   groupBox->setLayout(gl);
   
   char buf[32];
   ::qsnprintf(buf, sizeof(buf), "0x%08X", (unsigned int)get_screen_ea());
   mem_start = new QLineEdit(buf);
   mem_start->setValidator(&aiv);
   mem_values = new QLineEdit(this);

   address->setBuddy(mem_start);
   values->setBuddy(mem_values);
   
   type_byte->setChecked(true);
   
   QVBoxLayout *vbl = new QVBoxLayout();
   vbl->setSpacing(2);
   vbl->setContentsMargins(4, 4, 4, 4);
   vbl->addWidget(address);
   vbl->addWidget(mem_start);
   vbl->addWidget(new QWidget());
   vbl->addWidget(new QWidget());
   
   QWidget *leftPanel = new QWidget();
   leftPanel->setLayout(vbl);
   
   QHBoxLayout *hbl = new QHBoxLayout();
   hbl->setSpacing(2);
   hbl->setContentsMargins(4, 4, 4, 4);
   hbl->addWidget(leftPanel);
   hbl->addWidget(groupBox);
   
   QWidget *topPanel = new QWidget();
   topPanel->setLayout(hbl);
   
   QVBoxLayout *mainLayout = new QVBoxLayout();
   mainLayout->setSpacing(2);
   mainLayout->setContentsMargins(4, 4, 4, 4);
   mainLayout->addWidget(topPanel);
   mainLayout->addWidget(values);
   mainLayout->addWidget(mem_values);
   mainLayout->addWidget(buttonPanel);
   
   setLayout(mainLayout);
      
   connect(set_ok, SIGNAL(clicked()), this, SLOT(do_ok()));
   connect(set_cancel, SIGNAL(clicked()), this, SLOT(reject()));
   
   setWindowTitle("Set Memory Values");   
}

void showInformationMessage(const char *title, const char *msg) {
   QMessageBox::information(getWidgetParent(), title, msg);
}

void showWaitCursor() {
   QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
}

void restoreCursor() {
   QApplication::restoreOverrideCursor();
}

static QString &formatReg(QString &qs, const char *format, unsigned int val) {
   char buf[32];
   ::qsnprintf(buf, sizeof(buf), format, val);
   qs = buf;
   return qs;
}

void changeReg(int reg, const QString &val) {
   setRegisterValue(reg, strtoul(val.toAscii().data(), NULL, 0));
}

void MSP430Dialog::changePC() {
   changeReg(PC, QPC->text());
}

void MSP430Dialog::changeSP() {
   changeReg(SP, QSP->text());
}

void MSP430Dialog::changeSR() {
   changeReg(SR, QSR->text());
}

void MSP430Dialog::changeCG() {
   changeReg(CG, QCG->text());
}

void MSP430Dialog::changeR4() {
   changeReg(R4, QR4->text());
}

void MSP430Dialog::changeR5() {
   changeReg(R5, QR5->text());
}

void MSP430Dialog::changeR6() {
   changeReg(R6, QR6->text());
}

void MSP430Dialog::changeR7() {
   changeReg(R7, QR7->text());
}

void MSP430Dialog::changeR8() {
   changeReg(R8, QR8->text());
}

void MSP430Dialog::changeR9() {
   changeReg(R9, QR9->text());
}

void MSP430Dialog::changeR10() {
   changeReg(R10, QR10->text());
}

void MSP430Dialog::changeR11() {
   changeReg(R11, QR11->text());
}

void MSP430Dialog::changeR12() {
   changeReg(R12, QR12->text());
}

void MSP430Dialog::changeR13() {
   changeReg(R13, QR13->text());
}

void MSP430Dialog::changeR14() {
   changeReg(R14, QR14->text());
}

void MSP430Dialog::changeR15() {
   changeReg(R15, QR15->text());
}

//ask user for an address range and dump that address range
//to a user named file;
void MSP430Dialog::dumpRange() {
   ::dumpRange();
}

void MSP430Dialog::reset() {
   doReset();
}

void MSP430Dialog::breakOnSyscalls() {
   if (getBreakMode()) {
      emulateBreakOnSyscallsAction->setChecked(false);
   }
   else {
      emulateBreakOnSyscallsAction->setChecked(true);
   }
   setBreakMode(!getBreakMode());
}

void MSP430Dialog::microCorruptionBugs() {
   if (getBugMode()) {
      emulateMicrocorruptionBugModeAction->setChecked(false);
   }
   else {
      emulateMicrocorruptionBugModeAction->setChecked(true);
   }
   setBugMode(!getBugMode());
}

void MSP430Dialog::trackExec() {
   if (getTracking()) {
      emulateTrack_fetched_bytesAction->setChecked(false);
   }
   else {
      emulateTrack_fetched_bytesAction->setChecked(true);
   }
   setTracking(!getTracking());
}

void MSP430Dialog::traceExec() {
   if (getTracing()) {
      emulateTrace_executionAction->setChecked(false);
      closeTrace();
   }
   else {
      emulateTrace_executionAction->setChecked(true);
      openTraceFile();
   }
   setTracing(!getTracing()); 
}

void MSP430Dialog::setBreak() {
   setBreakpoint();
}

void MSP430Dialog::clearBreak() {
   clearBreakpoint();
}

void MSP430Dialog::hideEmu() {
   msp430Dlg->hide();
}

void MSP430Dialog::step() {
   stepOne();
}

void MSP430Dialog::skip() {
   ::skip();
}

void MSP430Dialog::run() {
   BREAK->setEnabled(true);
   ::run();
   BREAK->setEnabled(false);
}

void MSP430Dialog::doBreak() {
   shouldBreak = 1;
}

void MSP430Dialog::runCursor() {
   BREAK->setEnabled(true);
   ::runToCursor();
   BREAK->setEnabled(false);
}

void MSP430Dialog::jumpCursor() {
   ::jumpToCursor();
}

//ask the user for space separated data and push it onto the
//stack in right to left order as a C function would
void MSP430Dialog::pushData() {
   ::pushData();
}

void MSP430Dialog::setMemory() {
   SetMemoryDialog mem(this);
   mem.exec();
}

#define MSP430_WINDOW_FLAGS Qt::CustomizeWindowHint | \
                         Qt::WindowTitleHint | \
                         Qt::WindowMinimizeButtonHint | \
                         Qt::WindowCloseButtonHint | \
                         Qt::Tool
MSP430Dialog::MSP430Dialog(QWidget *parent) : QMainWindow(parent, MSP430_WINDOW_FLAGS) {   
   QAction *fileDumpAction = new QAction("Dump", this);
   QAction *fileCloseAction = new QAction("Close", this);   
   QAction *viewResetAction = new QAction("Reset", this);
   QAction *emulateSet_breakpointAction = new QAction("Set breakpoint...", this);
   QAction *emulateRemove_breakpointAction = new QAction("Remove breakpoint...", this);

   emulateBreakOnSyscallsAction = new QAction("Break on system call", this);
   emulateBreakOnSyscallsAction->setCheckable(true);

   emulateMicrocorruptionBugModeAction = new QAction("Emulate microcorruption bugs", this);
   emulateMicrocorruptionBugModeAction->setCheckable(true);

   emulateTrack_fetched_bytesAction = new QAction("Track fetched bytes", this);
   emulateTrack_fetched_bytesAction->setCheckable(true);

   emulateTrace_executionAction = new QAction("Trace execution", this);
   emulateTrace_executionAction->setCheckable(true);

   QPC = new QLineEdit();
   QPC->setValidator(&aiv);
   QFont font1;
   font1.setFamily(QString::fromUtf8("Courier"));
   QPC->setFont(font1);
   QPC->setFixedWidth(70);

   QSP = new QLineEdit();
   QSP->setValidator(&aiv);
   QSP->setFont(font1);
   QSP->setFixedWidth(70);

   QSR = new QLineEdit();
   QSR->setValidator(&aiv);
   QSR->setFont(font1);
   QSR->setFixedWidth(70);

   QCG = new QLineEdit();
   QCG->setValidator(&aiv);
   QCG->setFont(font1);
   QCG->setFixedWidth(70);

   QR9 = new QLineEdit();
   QR9->setValidator(&aiv);
   QR9->setFont(font1);
   QR9->setFixedWidth(70);

   QR6 = new QLineEdit();
   QR6->setValidator(&aiv);
   QR6->setFont(font1);
   QR6->setFixedWidth(70);

   QR7 = new QLineEdit();
   QR7->setValidator(&aiv);
   QR7->setFont(font1);
   QR7->setFixedWidth(70);

   QR5 = new QLineEdit();
   QR5->setValidator(&aiv);
   QR5->setFont(font1);
   QR5->setFixedWidth(70);

   QR4 = new QLineEdit();
   QR4->setValidator(&aiv);
   QR4->setFont(font1);
   QR4->setFixedWidth(70);

   QR8 = new QLineEdit();
   QR8->setValidator(&aiv);
   QR8->setFont(font1);
   QR8->setFixedWidth(70);

   QR10 = new QLineEdit();
   QR10->setValidator(&aiv);
   QR10->setFont(font1);
   QR10->setFixedWidth(70);

   QR11 = new QLineEdit();
   QR11->setValidator(&aiv);
   QR11->setFont(font1);
   QR11->setFixedWidth(70);

   QR12 = new QLineEdit();
   QR12->setValidator(&aiv);
   QR12->setFont(font1);
   QR12->setFixedWidth(70);

   QR13 = new QLineEdit();
   QR13->setValidator(&aiv);
   QR13->setFont(font1);
   QR13->setFixedWidth(70);

   QR14 = new QLineEdit();
   QR14->setValidator(&aiv);
   QR14->setFont(font1);
   QR14->setFixedWidth(70);

   QR15 = new QLineEdit();
   QR15->setValidator(&aiv);
   QR15->setFont(font1);
   QR15->setFixedWidth(70);

   QFormLayout *left = new QFormLayout();
   left->setSpacing(2);
   left->setContentsMargins(4, 4, 4, 4);
   //add label/Edit pairs
   left->addRow("PC", QPC);
   left->addRow("R4", QR4);
   left->addRow("R8", QR8);
   left->addRow("R12", QR12);

   QWidget *leftPanel = new QWidget();
   leftPanel->setLayout(left);

   QFormLayout *c1 = new QFormLayout();
   c1->setSpacing(2);
   c1->setContentsMargins(4, 4, 4, 4);
   //add label/Edit pairs
   c1->addRow("SP", QSP);
   c1->addRow("R5", QR5);
   c1->addRow("R9", QR9);
   c1->addRow("R13", QR13);

   QWidget *c1Panel = new QWidget();
   c1Panel->setLayout(c1);

   QFormLayout *c2 = new QFormLayout();
   c2->setSpacing(2);
   c2->setContentsMargins(4, 4, 4, 4);
   //add label/Edit pairs
   c2->addRow("SR", QSR);
   c2->addRow("R6", QR6);
   c2->addRow("R10", QR10);
   c2->addRow("R14", QR14);

   QWidget *c2Panel = new QWidget();
   c2Panel->setLayout(c2);

   QFormLayout *right = new QFormLayout();
   right->setSpacing(2);
   right->setContentsMargins(4, 4, 4, 4);
   right->addRow("CG", QCG);
   right->addRow("R7", QR7);
   right->addRow("R11", QR11);
   right->addRow("R15", QR15);

   QWidget *rightPanel = new QWidget();
   rightPanel->setLayout(right);

   QHBoxLayout *regBox = new QHBoxLayout();  //for registers
   regBox->setSpacing(2);
   regBox->setContentsMargins(4, 4, 4, 4);
   regBox->addWidget(leftPanel);
   regBox->addWidget(c1Panel);
   regBox->addWidget(c2Panel);
   regBox->addWidget(rightPanel);

   QGroupBox *REGISTERS = new QGroupBox("Registers");
   REGISTERS->setLayout(regBox);

   QPushButton *SET_MEMORY = new QPushButton("Set Memory");
   QPushButton *RUN = new QPushButton("Run");
   BREAK = new QPushButton("Break");
   QPushButton *SKIP = new QPushButton("Skip");
   QPushButton *STEP = new QPushButton("Step");
   QPushButton *RUN_TO_CURSOR = new QPushButton("Run to cursor");
   QPushButton *PUSH_DATA = new QPushButton("Push data");
   QPushButton *JUMP_TO_CURSOR = new QPushButton("Jump to cursor");
   
   QGridLayout *gl = new QGridLayout(); //for buttons
   gl->setSpacing(2);
   gl->setContentsMargins(4, 4, 4, 4);
   //add buttons
   gl->addWidget(STEP, 0, 0);
   gl->addWidget(RUN_TO_CURSOR, 0, 1);
   gl->addWidget(SKIP, 1, 0);
   gl->addWidget(JUMP_TO_CURSOR, 1, 1);
   gl->addWidget(RUN, 2, 0);
   gl->addWidget(BREAK, 2, 1);
   gl->addWidget(SET_MEMORY, 4, 0);
   gl->addWidget(PUSH_DATA, 4, 1);
   
   QWidget *buttons = new QWidget();
   buttons->setLayout(gl);

   QHBoxLayout *hbl = new QHBoxLayout();
   hbl->setSpacing(2);
   hbl->setContentsMargins(4, 4, 4, 4);
   hbl->addWidget(REGISTERS);
   hbl->addWidget(buttons);

   QWidget *central = new QWidget(this);
   central->setLayout(hbl);
   
   setCentralWidget(central);

   QToolBar *toolBar = new QToolBar();
   toolBar->setMovable(false);

   QMenu *File = new QMenu("File", this);
   QMenu *Edit = new QMenu("Edit", this);
   QMenu *View = new QMenu("View", this);
   QMenu *Emulate = new QMenu("Emulate", this);

   addToolBar(toolBar);
      
   setTabOrder(QPC, QSP);
   setTabOrder(QSP, QSR);
   setTabOrder(QSR, QCG);
   setTabOrder(QCG, QR4);
   setTabOrder(QR4, QR5);
   setTabOrder(QR5, QR6);
   setTabOrder(QR6, QR7);
   setTabOrder(QR7, QR8);
   setTabOrder(QR8, QR9);
   setTabOrder(QR9, QR10);
   setTabOrder(QR10, QR11);
   setTabOrder(QR11, QR12);
   setTabOrder(QR12, QR13);
   setTabOrder(QR13, QR14);
   setTabOrder(QR14, QR15);
   setTabOrder(QR15, STEP);
   setTabOrder(STEP, RUN_TO_CURSOR);
   setTabOrder(RUN_TO_CURSOR, SKIP);
   setTabOrder(SKIP, JUMP_TO_CURSOR);
   setTabOrder(JUMP_TO_CURSOR, RUN);
   setTabOrder(RUN, SET_MEMORY);
   setTabOrder(SET_MEMORY, PUSH_DATA);

   toolBar->addAction(File->menuAction());
   toolBar->addAction(Edit->menuAction());
   toolBar->addAction(View->menuAction());
   toolBar->addAction(Emulate->menuAction());

   File->addAction(fileDumpAction);
   File->addSeparator();
   File->addAction(fileCloseAction);

   View->addAction(viewResetAction);
   Emulate->addAction(emulateSet_breakpointAction);
   Emulate->addAction(emulateRemove_breakpointAction);
   Emulate->addSeparator();
   Emulate->addAction(emulateBreakOnSyscallsAction);
   Emulate->addAction(emulateMicrocorruptionBugModeAction);
   Emulate->addSeparator();
   Emulate->addAction(emulateTrack_fetched_bytesAction);
   Emulate->addAction(emulateTrace_executionAction);
   
   connect(STEP, SIGNAL(clicked()), this, SLOT(step()));
   connect(SKIP, SIGNAL(clicked()), this, SLOT(skip()));
   connect(RUN, SIGNAL(clicked()), this, SLOT(run()));
   connect(BREAK, SIGNAL(clicked()), this, SLOT(doBreak()));
   connect(RUN_TO_CURSOR, SIGNAL(clicked()), this, SLOT(runCursor()));
   connect(JUMP_TO_CURSOR, SIGNAL(clicked()), this, SLOT(jumpCursor()));
   connect(SET_MEMORY, SIGNAL(clicked()), this, SLOT(setMemory()));
   connect(PUSH_DATA, SIGNAL(clicked()), this, SLOT(pushData()));
   connect(QPC, SIGNAL(editingFinished()), this, SLOT(changePC()));
   connect(QSP, SIGNAL(editingFinished()), this, SLOT(changeSP()));
   connect(QSR, SIGNAL(editingFinished()), this, SLOT(changeSR()));
   connect(QCG, SIGNAL(editingFinished()), this, SLOT(changeCG()));
   connect(QR4, SIGNAL(editingFinished()), this, SLOT(changeR4()));
   connect(QR5, SIGNAL(editingFinished()), this, SLOT(changeR5()));
   connect(QR6, SIGNAL(editingFinished()), this, SLOT(changeR6()));
   connect(QR7, SIGNAL(editingFinished()), this, SLOT(changeR7()));
   connect(QR8, SIGNAL(editingFinished()), this, SLOT(changeR8()));
   connect(QR9, SIGNAL(editingFinished()), this, SLOT(changeR9()));
   connect(QR10, SIGNAL(editingFinished()), this, SLOT(changeR10()));
   connect(QR11, SIGNAL(editingFinished()), this, SLOT(changeR11()));
   connect(QR12, SIGNAL(editingFinished()), this, SLOT(changeR12()));
   connect(QR13, SIGNAL(editingFinished()), this, SLOT(changeR13()));
   connect(QR14, SIGNAL(editingFinished()), this, SLOT(changeR14()));
   connect(QR15, SIGNAL(editingFinished()), this, SLOT(changeR15()));

   connect(fileDumpAction, SIGNAL(triggered()), this, SLOT(dumpRange()));
   connect(fileCloseAction, SIGNAL(triggered()), this, SLOT(hideEmu()));
   connect(emulateSet_breakpointAction, SIGNAL(triggered()), this, SLOT(setBreak()));
   connect(emulateRemove_breakpointAction, SIGNAL(triggered()), this, SLOT(clearBreak()));
   connect(viewResetAction, SIGNAL(triggered()), this, SLOT(reset()));

   connect(emulateBreakOnSyscallsAction, SIGNAL(triggered()), this, SLOT(breakOnSyscalls()));
   connect(emulateMicrocorruptionBugModeAction, SIGNAL(triggered()), this, SLOT(microCorruptionBugs()));
   connect(emulateTrack_fetched_bytesAction, SIGNAL(triggered()), this, SLOT(trackExec()));
   connect(emulateTrace_executionAction, SIGNAL(triggered()), this, SLOT(traceExec()));

   setWindowTitle("msp430 Emulator");

}

bool createEmulatorWindow() {
   if (msp430Dlg == NULL) {
      msp430Dlg = new MSP430Dialog(getWidgetParent());
      setTitle();
      syncDisplay();
   }
   return true;
}

void destroyEmulatorWindow() {
   if (msp430Dlg) {
      msp430Dlg->close();
      delete msp430Dlg;
      msp430Dlg = NULL; 
   }
}

void displayEmulatorWindow() {
   if (msp430Dlg == NULL) {
      createEmulatorWindow();
   }
   msp430Dlg->show();
}

void CustomInputDialog::do_ok() {
   const char *v = inputText->text().toAscii().data();
   unsigned int dlen = inputText->text().length();

   if (hex_or_not->isChecked()) {
      unsigned int count = 0;      
      unsigned char *udata = (unsigned char *)::qalloc(dlen);
      unsigned int i = 0;
      unsigned char *p = udata;
      for (; i < dlen; i++) {
         if (!isspace(v[i])) {
            *p++ = (unsigned char)v[i];
         }
      }
      dlen = p - udata;
      i = 0;
      for (i = 0; i < dlen && count < _max; i += 2, count++) {
         if (sscanf(v + i, "%2hhx", udata + count) != 1) {
            QMessageBox::warning(getWidgetParent(), "Invalid input", "Invalid characters in hex input");            
            ::qfree(udata);
            return;
         }
      }
      data.append(udata, count);
      ::qfree(udata);   
   }
   else {
      if (dlen > _max) {
         dlen = _max;
      }
      data.append(v, dlen);
   }
   accept();
}

CustomInputDialog::CustomInputDialog(const char *console, unsigned int max, QWidget *parent) : _max(max), QDialog(parent) {
   setSizeGripEnabled(false);
   setModal(true);

   QPlainTextEdit *text = new QPlainTextEdit(console, this);
   text->setReadOnly(true);

   QLabel *label1 = new QLabel("The CPU has requested user input from the console. Below is the output displayed on the console.");
   QLabel *label2 = new QLabel("Enter input below:");
   
   hex_or_not = new QCheckBox("Check here if entering hex encoded input.", this);
   inputText = new QLineEdit(this);

   QPushButton *btn_send = new QPushButton("&send");
   btn_send->setAutoDefault(true);
   btn_send->setDefault(true);
   
   QPushButton *btn_wait = new QPushButton("&wait");
   btn_send->setAutoDefault(true);
   
   QHBoxLayout *buttonLayout = new QHBoxLayout();
   buttonLayout->setSpacing(2);
   buttonLayout->setContentsMargins(4, 4, 4, 4);
   buttonLayout->addStretch(1);
   buttonLayout->addWidget(btn_send);
   buttonLayout->addWidget(btn_wait);
   buttonLayout->addStretch(1);
   
   QWidget *buttonPanel = new QWidget();
   buttonPanel->setLayout(buttonLayout);
   
//   address->setBuddy(mem_start);
//   values->setBuddy(mem_values);

   QVBoxLayout *cbl = new QVBoxLayout();
   cbl->setSpacing(4);
   cbl->setContentsMargins(4, 4, 4, 4);
   cbl->addWidget(label2);
   cbl->addWidget(hex_or_not);
   
   QWidget *cbPanel = new QWidget();
   cbPanel->setLayout(cbl);   

   QHBoxLayout *hbl = new QHBoxLayout();
   hbl->setSpacing(2);
   hbl->setContentsMargins(4, 4, 4, 4);
   hbl->addWidget(inputText);
   hbl->addWidget(buttonPanel);
   
   QWidget *inputPanel = new QWidget();
   inputPanel->setLayout(hbl);   
   
   QVBoxLayout *vbl = new QVBoxLayout();
   vbl->setSpacing(4);
   vbl->setContentsMargins(8, 8, 8, 8);
   vbl->addWidget(label1);
   vbl->addWidget(text);
   vbl->addWidget(cbPanel);
   vbl->addWidget(inputPanel);

   setLayout(vbl);
      
   connect(btn_send, SIGNAL(clicked()), this, SLOT(do_ok()));
   connect(btn_wait, SIGNAL(clicked()), this, SLOT(reject()));
   
   setWindowTitle("IO interrupt triggered");   
}


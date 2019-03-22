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

/*
 *  This is the msp430 Emulation plugin module
 *
 *  It is known to compile with
 *
 *  - Qt Version: Windows - Visual Studio 2008, Linux/OS X - g++
 *  - Windows only version (IDA < 6.0): Visual C++ 6.0, Visual Studio 2005, MinGW g++/make
 *
 */

#ifdef __NT__
#include <windows.h>
#include <winnt.h>
#include <wincrypt.h>
#else
//#ifndef __NT__
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#endif

#ifdef PACKED
#undef PACKED
#endif

#ifndef __QT__
#include "msp430emu_ui.h"
#else
#include "msp430emu_ui_qt.h"
#endif

#include "msp430defs.h"
#include "cpu.h"

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <auto.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <nalt.hpp>
#include <segment.hpp>
#if IDA_SDK_VERSION >= 700
#include <segregs.hpp>
#else
#include <srarea.hpp>
#endif
#include <typeinf.hpp>
#include <struct.hpp>
#include <entry.hpp>

#include "break.h"
#include "emu_script.h"
#include "buffer.h"

#ifndef DEBUG
//#define DEBUG 1
#endif

#if IDA_SDK_VERSION >= 700
TWidget *mainForm;
TWidget *stackCC;
#else
TForm *mainForm;
TCustomControl *stackCC;
#endif

#ifdef __NT__
HCRYPTPROV hProv;
#else
int hProv = -1;
#endif

unsigned int randVal;

// The magic number for verifying the database blob
static const int MSP430EMU_BLOB_MAGIC = 0x50534365;  // "eMSP"

//The version number with which to tag the data in the
//database storage node
static const int MSP430EMU_BLOB_VERSION_MAJOR = 0;
static const int MSP430EMU_BLOB_VERSION_MINOR = 1;

//The node name to use to identify the plug-in's storage
//node in the IDA database.
static const char msp430emu_node_name[] = "$ MSP430 CPU emulator state";

//The IDA database node identifier into which the plug-in will
//store its state information when the database is saved.
netnode msp430emu_node(msp430emu_node_name);

//set to true if saved emulator state is found
bool cpuInit = false;

#if IDA_SDK_VERSION >= 700
bool idaapi run(size_t);
#else
void idaapi run(int);
#endif

//tracking and tracing enable
bool doTrace = false;
FILE *traceFile = NULL;
bool doTrack = false;

//microcorruption bug mode enable
bool bugMode = false;

bool idpHooked = false;
bool idbHooked = false;
bool uiHooked = false;

bool isWindowCreated = false;

#if IDA_SDK_VERSION >= 700
static ssize_t idaapi idpCallback(void * cookie, int code, va_list va);
#else
static int idaapi idpCallback(void * cookie, int code, va_list va);
#endif

void getRandomBytes(void *buf, unsigned int len) {
#ifdef __NT__
   if (hProv == 0) {
      CryptAcquireContext(&hProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
   }
   CryptGenRandom(hProv, len, (BYTE*)buf);
#else
   if (hProv == -1) {
      hProv = open("/dev/urandom", O_RDONLY);
   }
   read(hProv, buf, len);
#endif
}

/*
 * Add a trace entry to the trace log
 */
void traceLog(char *entry) {
   if (traceFile != NULL) {
      qfprintf(traceFile, "%s", entry);
   }
   else {
      //should never get here, but if we do just dump to message window
      msg("%s", entry);
   }
}

void setBugMode(bool newMode) {
   bugMode = newMode;
}

bool getBugMode() {
   return bugMode;
}

void setTracking(bool track) {
   doTrack = track;
}

bool getTracking() {
   return doTrack;
}

void setTracing(bool trace) {
   doTrace = trace;
}

bool getTracing() {
   return doTrace;
}

void closeTrace() {
   if (traceFile) {  //just in case a trace is already open
      qfclose(traceFile);
      traceFile = NULL;
   }
}

void openTraceFile() {
   char buf[260];
#ifndef __QT__
   const char *filter = "All (*.*)\0*.*\0Trace files (*.trc)\0*.trc\0";
#else
   const char *filter = "All (*.*);;Trace files (*.trc)";
#endif
   char *fname = getSaveFileName("Open trace file", buf, sizeof(buf), filter);
   if (fname) {
      closeTrace();
      traceFile = qfopen(fname, "w");
   }
}

/*
 * Set the title of the emulator window
 */
void setTitle() {
   setEmulatorTitle("MSP430 Emulator");
}

//convert a control ID to a pointer to the corresponding register
unsigned int *toReg(unsigned int reg) {
   //offsets from control ID to register set array index
   if (reg < 16) {
      return &cpu.general[reg];
   }
   return NULL;
}

//convert a control ID to a pointer to the corresponding register
unsigned int *getRegisterPointer(unsigned int reg) {
   if (reg < 16) {
      return &cpu.general[reg];
   }
   return NULL;
}

//convert a control ID to a pointer to the corresponding register
unsigned int getRegisterValue(int reg) {
   unsigned int *rp = getRegisterPointer(reg);
   if (rp) {
      return *rp;
   }
   return 0;
}

void setRegisterValue(int reg, unsigned int val) {
   unsigned int *rp = getRegisterPointer(reg);
   if (rp) {
      *rp = val & 0xffff;
   }
}

//update all register displays from existing register values
//useful after a breakpoint or "run to"
//i.e. synchronize the display to the actual cpu/memory values
void syncDisplay() {
   for (int i = MIN_REG; i <= MAX_REG; i++) {
      updateRegisterDisplay(i);
   }
   if (find_tform("IDA View-Stack")) {
      idaplace_t p(sp, 0);
      jumpto(stackCC, &p, 0, 0);
      do_data_ex(sp, wordflag(), 2, BADNODE);      
   }
   switchto_tform(mainForm, false);
   jumpto(pc);
}

//force conversion to code at the current eip location
void forceCode() {
#if IDA_SDK_VERSION >= 540
   int len = create_insn(pc);
#else
   int len = ua_ana0(pc);
#endif
#ifdef DOUNK_EXPAND
   do_unknown_range(pc, len, DOUNK_EXPAND | DOUNK_DELNAMES);
#else
   do_unknown_range(pc, len, true);
#endif
   auto_make_code(pc); //make code at eip, or ua_code(pc);
}

//Tell IDA that the thing at the current eip location is
//code and ask it to change the display as appropriate.
void codeCheck(void) {
   ea_t loc = pc;
   ea_t head = get_item_head(loc);
   if (isUnknown(getFlags(loc))) {
      forceCode(); //or ua_code(loc);
   }
   else if (loc != head) {
      do_unknown(head, true); //undefine it
      forceCode(); //or ua_code(loc);
   }
   else if (!isCode(getFlags(loc))) {
      do_unknown(loc, true); //undefine it
      forceCode(); //or ua_code(loc);
   }
/*
   int len1 = get_item_size(loc);
#if IDA_SDK_VERSION >= 540
   int len2 = create_insn(loc);
#else
   int len2 = ua_ana0(loc);
#endif
   if (len1 != len2) {
      forceCode(); //or ua_code(loc);
   }
   else if (isUnknown(getFlags(loc))) {
      forceCode(); //or ua_code(loc);
   }
   else if (!isHead(getFlags(loc)) || !isCode(getFlags(loc))) {
//      while (!isHead(getFlags(loc))) loc--; //find start of current
      loc = get_item_head(loc);
      do_unknown(loc, true); //undefine it
      forceCode();
   }
*/
}

//update the specified register display with the specified
//value.  useful to update register contents based on user
//input
void updateRegister(unsigned int r, unsigned int val) {
   setRegisterValue(r, val);
   updateRegisterDisplay(r);
}

//set a register from idc.
void setIdcRegister(unsigned int idc_reg_num, unsigned int newVal) {
   updateRegister(idc_reg_num, newVal);
}

unsigned int parseNumber(char *numb) {
   unsigned int val = (unsigned int)strtol(numb, NULL, 0); //any base
   if (val == 0x7FFFFFFF) {
      val = strtoul(numb, NULL, 0); //any base
   }
   return val;
}

//ask the user for space separated data and push it onto the
//stack in right to left order as a C function would
void pushData() {
   int count = 0;
   char *data = inputBox("Push Stack Data", "Enter space separated data", "");
   if (data) {
      char *ptr;
      while ((ptr = strrchr(data, ' ')) != NULL) {
         *ptr++ = 0;
         if (strlen(ptr)) {
            unsigned short val = parseNumber(ptr);
            push(val);
            count++;
         }
      }
      if (strlen(data)) {
         unsigned short val = parseNumber(data);
         push(val);
         count++;
      }
      syncDisplay();
   }
}

//ask user for an address range and dump that address range
//to a user named file;
void dumpRange(unsigned int low, unsigned int hi) {
   char buf[80];
   ::qsnprintf(buf, sizeof(buf), "0x%04X-0x%04X", low, hi);
   char *range = inputBox("Enter Range", "Enter the address range to dump (inclusive)", buf);
   if (range) {
      char *end;
      unsigned int start = strtoul(range, &end, 0);
      if (end) {
         unsigned int finish = strtoul(++end, NULL, 0);
         char szFile[260];       // buffer for file name
#ifndef __QT__
         const char *filter = "All (*.*)\0*.*\0Binary (*.bin)\0*.BIN\0Executable (*.exe)\0*.EXE\0Dynamic link library (*.dll)\0*.DLL\0";
#else
         const char *filter = "All (*.*);;Binary (*.bin);;Executable (*.exe);;Dynamic link library (*.dll)";
#endif
         char *fname = getSaveFileName("Dump bytes to file", szFile, sizeof(szFile), filter);
         if (fname) {
            FILE *f = qfopen(szFile, "wb");
            if (f) {
               base2file(f, 0, start, finish);
/*
               for (; start <= finish; start++) {
                  unsigned char val = readByte(start);
                  qfwrite(&val, 1, 1, f);
               }
*/
               qfclose(f);
            }
         }
      }
   }
}

//ask user for an address range and dump that address range
//to a user named file;
void dumpRange() {
   dumpRange((unsigned int)get_screen_ea(), 0x10000);
}

//ask user for a file name and load the entire file into memory
//at the specified address
void memLoadFile(unsigned short start) {
   char szFile[260];       // buffer for file name
   unsigned char buf[512];
   int readBytes;
   unsigned int addr = start;
#ifndef __QT__
   const char *filter = "All (*.*)\0*.*\0";
#else
   const char *filter = "All (*.*)";
#endif
   szFile[0] = 0;
   char *fileName = getOpenFileName("Load memory from file", szFile, sizeof(szFile), filter);
   if (fileName) {
      FILE *f = qfopen(szFile, "rb");
      if (f) {
         while ((readBytes = qfread(f, buf, sizeof(buf))) > 0) {
            patch_many_bytes(addr, buf, readBytes);
            addr += readBytes;
   /*
            ptr = buf;
            for (; readBytes > 0; readBytes--) {
               writeMem(addr++, *ptr++, SIZE_BYTE);
            }
   */
         }
         qfclose(f);
      }
      msg("msp430emu: Loaded 0x%X bytes from file %s to address 0x%X\n", addr - start, szFile, start);
   }
}

//skip the instruction at eip
void skip() {
   //this relies on IDA's decoding, not our own
   pc += (unsigned short)get_item_size(pc);
   syncDisplay();
}

void grabStackBlock() {
   char msg_buf[128];
   char *bytes = inputBox("Stack space", "How many bytes of stack space?", "");
   if (bytes) {
      char *endptr;
      unsigned int size = strtoul(bytes, &endptr, 0);
      if (*endptr) {
         ::qsnprintf(msg_buf, sizeof(msg_buf), "Invalid number: %s, cancelling stack allocation", bytes);
         showErrorMessage(msg_buf);
         return;
      }
      size = (size + 3) & ~3;
      if (size) {
         sp -= size;
         ::qsnprintf(msg_buf, sizeof(msg_buf), "%d bytes allocated in the stack at 0x%08x", size, sp);
         showInformationMessage("Success", msg_buf);
         updateRegisterDisplay(SP);
      }
      else {
         showErrorMessage("No bytes were allocated in the stack");
      }
   }
}

void stepOne() {
   codeCheck();
   executeInstruction();
   codeCheck();
   syncDisplay();
}

//use after tracing with no updates
void emuSyncDisplay() {
   codeCheck();
   syncDisplay();
}

//step the emulator one instruction without
//updating any emulator displays
void traceOne() {
   executeInstruction();
}

//let the emulator run
//only stops when it hist a breakpoint or when
//signaled to break
void run() {
   codeCheck();
   showWaitCursor();
   //tell the cpu that we want to run free
   shouldBreak = 0;
   //always execute at least one instruction this helps when
   //we are running from an existing breakpoint
   executeInstruction();
   while (!isBreakpoint(pc) && !shouldBreak) {
      executeInstruction();
   }
   syncDisplay();
   restoreCursor();
}

void trace() {
   codeCheck();
   showWaitCursor();
   //tell the cpu that we want to run free
   shouldBreak = 0;
   //always execute at least one instruction this helps when
   //we are running from an existing breakpoint
   executeInstruction();
   while (!isBreakpoint(pc) && !shouldBreak) {
      executeInstruction();
   }
   restoreCursor();
}

//
// Called by IDA to notify the plug-in of certain UI events.
// At the moment this is only used to catch the "saving" event
// so that the plug-in can save its state in the database.
//
#if IDA_SDK_VERSION >= 700
static ssize_t idaapi uiCallback(void * /*cookie*/, int code, va_list /*va*/) {
#else
static int idaapi uiCallback(void * /*cookie*/, int code, va_list /*va*/) {
#endif
   switch (code) {
   case ui_saving: {
      //
      // The user is saving the database.  Save the plug-in
      // state with it.
      //
#ifdef DEBUG
      msg(PLUGIN_NAME": ui_saving notification\n");
#endif
      Buffer *b = new Buffer();
      msp430emu_node.create(msp430emu_node_name);
      if (saveState(msp430emu_node) == MSP430EMUSAVE_OK) {
         msg("msp430emu: Emulator state was saved.\n");
      }
      else {
         msg("msp430emu: Emulator state save failed.\n");
      }
      delete b;
      break;
   }
   default:
      break;
   }
   return 0;
}

//
// Called by IDA to notify the plug-in of certain UI events.
// At the moment this is only used to catch the "saving" event
// so that the plug-in can save its state in the database.
//
#if IDA_SDK_VERSION >= 700
static ssize_t idaapi idpCallback(void * /*cookie*/, int code, va_list /*va*/) {
#else
static int idaapi idpCallback(void * /*cookie*/, int code, va_list /*va*/) {
#endif
   switch (code) {
#if IDA_SDK_VERSION >= 700
   case processor_t::ev_newfile: {
#else
   case processor_t::newfile: {
#endif
      //
      // a new database has been opened
      //
#ifdef DEBUG
      msg(PLUGIN_NAME": newfile notification\n");
#endif
      break;
   }
#if IDA_SDK_VERSION < 700
   case processor_t::closebase: {
#else
   case idb_event::closebase: {
#endif
#ifdef DEBUG
      msg(PLUGIN_NAME": closebase notification\n");
#endif
      break;
   }
#if IDA_SDK_VERSION >= 700
   case processor_t::ev_oldfile: {
#else
   case processor_t::oldfile: {
#endif
      //
      // See if there's a previous CPU state in this database that can
      // be used.
      //
      if (netnode_exist(msp430emu_node)) {
         //netnode should only exist if emulator was previously run
         // There's an msp430emu node in the database.  Attempt to
         // instantiate the CPU state from it.
         msg("msp430emu: Loading msp430emu state from existing netnode.\n");
         unsigned int loadStatus = loadState(msp430emu_node);

         if (loadStatus == MSP430EMULOAD_OK) {
            cpuInit = true;
         }
         else {
            //probably shouldn't continue trying to init emulator at this point
            msg("msp430emu: Error restoring msp430emu state: %d.\n", loadStatus);
         }

         randVal = (unsigned int)msp430emu_node.altval(MSP430_RANDVAL);

         if (randVal == 0) {
            do {
               getRandomBytes(&randVal, 4);
            } while (randVal == 0);
            msp430emu_node.altset(MSP430_RANDVAL, randVal);
         }
      }
      else {
         msg("msp430emu: No saved msp430emu state data was found.\n");
      }
      break;
   }
   default:
      break;
   }
   return 0;
}

void doReset() {
   resetCpu();
//   pc = (unsigned int)get_screen_ea();
   syncDisplay();
}

void jumpToCursor() {
   pc = (unsigned int)get_screen_ea();
   syncDisplay();
}

void runToCursor() {
   codeCheck();
   showWaitCursor();
   unsigned int endAddr = (unsigned int)get_screen_ea();
   //tell the cpu that we want to run free
   shouldBreak = 0;
   while (pc != endAddr && !shouldBreak) {
      executeInstruction();
   }
   syncDisplay();
   restoreCursor();
   codeCheck();
}

void setBreakpoint() {
   char loc[16];
   ::qsnprintf(loc, sizeof(loc), "0x%04X", (unsigned int)get_screen_ea());
   char *bpt = inputBox("Set Breakpoint", "Specify breakpoint location", loc);
   if (bpt) {
      unsigned int bp = strtoul(bpt, NULL, 0);
//                  sscanf(value, "%X", &bp);
      addBreakpoint(bp);
   }
}

void clearBreakpoint() {
   char loc[16];
   ::qsnprintf(loc, sizeof(loc), "0x%04X", (unsigned int)get_screen_ea());
   char *bpt = inputBox("Remove Breakpoint", "Specify breakpoint location", loc);
   if (bpt) {
//                  sscanf(value, "%X", &bp);
      unsigned int bp = strtoul(bpt, NULL, 0);
      removeBreakpoint(bp);
   }
}

//--------------------------------------------------------------------------
//
//      Initialize.
//
//      IDA will call this function only once.
//      If this function returns PLGUIN_SKIP, IDA will never load it again.
//      If this function returns PLUGIN_OK, IDA will unload the plugin but
//      remember that the plugin agreed to work with the database.
//      The plugin will be loaded again if the user invokes it by
//      pressing the hotkey or selecting it from the menu.
//      After the second load the plugin will stay on memory.
//      If this function returns PLUGIN_KEEP, IDA will keep the plugin
//      in the memory. In this case the initialization function can hook
//      into the processor module and user interface notification points.
//      See the hook_to_notification_point() function.
//
int idaapi init(void) {
   cpuInit = false;

   if (strcmp(inf.procName, "msp430")) return PLUGIN_SKIP;

//   msg(PLUGIN_NAME": hooking idp\n");
   hook_to_notification_point(HT_IDP, idpCallback, NULL);
   idpHooked = true;

   resetCpu();

   return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
//      Terminate.
//
//      IDA will call this function when the user asks to exit.
//      This function won't be called in the case of emergency exits.

void idaapi term(void) {
#ifdef DEBUG
   msg(PLUGIN_NAME": term entered\n");
#endif
   if (hProv) {
#ifdef __NT__
      CryptReleaseContext(hProv, 0);
#else
      close(hProv);
#endif
   }
   if (uiHooked) {
      unhook_from_notification_point(HT_UI, uiCallback, NULL);
      uiHooked = false;
      unregister_funcs();
   }
   if (idpHooked) {
      idpHooked = false;
      unhook_from_notification_point(HT_IDP, idpCallback, NULL);
   }
   destroyEmulatorWindow();
   closeTrace();
   doTrace = false;
   doTrack = false;
#ifdef DEBUG
   msg(PLUGIN_NAME": term exiting\n");
#endif
}

//--------------------------------------------------------------------------
//
//      The plugin method
//
//      This is the main function of plugin.
//
//      It will be called when the user selects the plugin.
//
//              arg - the input argument, it can be specified in
//                    plugins.cfg file. The default is zero.
//
//

#if IDA_SDK_VERSION >= 700
bool idaapi run(size_t /*arg*/) {
#else
void idaapi run(int /*arg*/) {
#endif
   if (!isWindowCreated) {
      if (!netnode_exist(msp430emu_node)) {
         //save basic info first time we encounter this database
         //BUT don't mark emulator as initialized
         //NOTE - should also save original PE headers as a blob at this point
         //they may not be available by the time the user decides to run the plugin
         msp430emu_node.create(msp430emu_node_name);
         getRandomBytes(&randVal, 4);
         msp430emu_node.altset(MSP430_RANDVAL, randVal);
      }

      if (!cpuInit) {
         unsigned int init_pc = get_word(0xfffe);
         if (init_pc == 0) {
            init_pc = (unsigned int)get_screen_ea();
         }
         else {
            jumpto(init_pc);
            auto_make_code(init_pc); //make code at eip, or ua_code(pc);
         }
         initProgram(init_pc);
      }

#if IDA_SDK_VERSION >= 530
#if IDA_SDK_VERSION >= 700
      TWidget *stackForm = open_disasm_window("Stack");
#else
      TForm *stackForm = open_disasm_window("Stack");
#endif
      switchto_tform(stackForm, true);
      stackCC = get_current_viewer();
      mainForm = find_tform("IDA View-A");
      switchto_tform(mainForm, true);
#endif
      if (!cpuInit) {
         pc = (unsigned int)get_screen_ea();
      }
      isWindowCreated = createEmulatorWindow();
   }
   if (isWindowCreated) {
      displayEmulatorWindow();
   }
   if (!uiHooked) {
      uiHooked = true;
      hook_to_notification_point(HT_UI, uiCallback, NULL);
      register_funcs();
   }
#if IDA_SDK_VERSION >= 700
   return true;
#endif
}

//--------------------------------------------------------------------------
char comment[] = "This is an MSP430 emulator";

char help[] = "";

//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "msp430 Emulator";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

char wanted_hotkey[] = "Alt-F5";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------

plugin_t PLUGIN = {
  IDP_INTERFACE_VERSION,
  PLUGIN_PROC,                    // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};

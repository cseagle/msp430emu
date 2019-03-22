/*
   Headers for MSP430 emulator
   Copyright (c) 2014, Chris Eagle
   
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

#ifndef __MSP430DEFS_H
#define __MSP430DEFS_H

#ifndef __IDP__

#ifndef WIN32

#include <sys/types.h>
typedef int64_t quad;
typedef u_int64_t uquad;

#else   //WIN32

typedef __int64 quad;
typedef unsigned __int64 uquad;

typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int u_int32_t;
typedef int int32_t;

#endif  //WIN32

typedef unsigned int   uint;
typedef unsigned short ushort;
typedef unsigned char  uchar;

// Use printf instead of msg when not using Ida
#define msg printf

#else   //#ifdef __IDP__

#ifndef NO_OBSOLETE_FUNCS
#define NO_OBSOLETE_FUNCS
#endif

#ifndef USE_DANGEROUS_FUNCTIONS
#define USE_DANGEROUS_FUNCTIONS
#endif  // USE_DANGEROUS_FUNCTIONS

#ifndef USE_STANDARD_FILE_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
#endif

#ifndef __NT__
#define _strdup strdup
#endif

#define PLUGIN_NAME "msp430emu"

#ifdef __QT__
#ifndef QT_NAMESPACE
#define QT_NAMESPACE QT
#endif
#endif

#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <netnode.hpp>

typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int u_int32_t;
typedef int int32_t;

#include "sdk_versions.h"

//Some idasdk70 transition macros
#if IDA_SDK_VERSION >= 700

#define startEA start_ea 
#define endEA end_ea 

#define minEA min_ea
#define maxEA max_ea
#define ominEA omin_ea
#define omaxEA omax_ea
#define procName procname

#define get_flags_novalue(ea) get_flags(ea)
#define isEnum0(f) is_enum0(f)
#define isEnum1(f) is_enum1(f)
#define isStroff0(f) is_stroff0(f)
#define isStroff1(f) is_stroff1(f)
#define isOff0(f) is_off0(f)
#define isOff1(f) is_off1(f)
#define isOff(f, n) is_off(f, n)
#define isEnum(f, n) is_enum(f, n)
#define isStroff(f, n) is_stroff(f, n)
#define isUnknown(f) is_unknown(f)
#define getFlags(f) get_flags(f)

#define isStruct(f) is_struct(f)
#define isASCII(f) is_strlit(f)
#define do_unknown(a, f) del_items(a, f)
#define do_unknown_range(a, s, f) del_items(a, f, s)
#define isCode(f) is_code(f)

#define get_member_name2 get_member_name

#define put_many_bytes(a, b, s) put_bytes(a, b, s)
#define patch_many_bytes(a, b, s) patch_bytes(a, b, s)
#define get_many_bytes(a, b, s) get_bytes(b, s, a)

#define do_data_ex(a, d, s, t) create_data(a, d, s, t)
#define doDwrd(a, l) create_dword(a, l)
#define doStruct(a, l, t) create_struct(a, l, t)

#define dwrdflag dword_flag
#define wordflag word_flag

#define isEnabled(a) is_mapped(a)
#define isLoaded(a) is_loaded(a)

#define switchto_tform(w, f) activate_widget(w, f)
#define find_tform(c) find_widget(c)

#define get_long(a) get_dword(a)
#define patch_long(a, v) patch_dword(a, v)
#define put_long(a, v) put_dword(a, v)

#define get_segreg(a, r) get_sreg(a, r)
#define set_default_segreg_value(s, r, v) set_default_sreg_value(s, r, v) 

#define AskUsingForm_c ask_form
#define askbuttons_c ask_buttons

#define alt1st altfirst
#define altnxt altnext
#define sup1st supfirst
#define supnxt supnext

#else

#define start_ea startEA
#define end_ea endEA

#define ev_add_cref add_cref
#define ev_add_dref add_dref
#define ev_del_cref del_cref
#define ev_del_dref del_dref
#define ev_oldfile oldfile
#define ev_newfile newfile
#define ev_auto_queue_empty auto_queue_empty

#define set_func_start func_setstart 
#define set_func_end func_setend

#define get_dword(a) get_long(a)
#define patch_dword(a, v) patch_long(a, v)
#define put_dword(a, v) put_long(a, v)

#define get_sreg(a, r) get_segreg(a, r)
#define set_default_sreg_value(s, r, v) set_default_segreg_value(s, r, v) 

#define altfirst alt1st
#define altnext  altnxt
#define supfirst sup1st
#define supnext  supnxt

#define get_bytes(b, s, a) get_many_bytes(a, b, s)

#define ask_form AskUsingForm_c
#define ask_buttons askbuttons_c

#endif

extern netnode msp430emu_node;
extern netnode kernel_node;

#endif

#define xCARRY 0x1
#define xZERO  0x2
#define xSIGN 0x4
#define xINTERRUPT 0x8
#define xCPUOFF 0x10
#define xOVERFLOW 0x100

#define xCF xCARRY
#define xZF xZERO
#define xSF xSIGN
#define xVF xOVERFLOW

#define RESERVED_FLAGS 0xFE00

#define SET(x) (sr |= (x))
#define CLEAR(x) (sr &= (~x))

#define xV (sr & xVF)
#define xNV (!(sr & xVF))

#define xB (sr & xCF)
#define xC xB
#define xNAE xB
#define xNB (!(sr & xCF))
#define xAE xNB
#define xNC xNB

#define xE (sr & xZF)
#define xZ xE
#define xNE (!(sr & xZF))
#define xNZ xNE

#define xBE (sr & (xZF | xCF))
#define xNA xBE
#define xNBE (!(sr & (xZF | xCF)))
#define xA xNBE

#define xS (sr & xSF)
#define xN xS
#define xNS (!(sr & xSF))

#define xL (((sr & (xSF | xVF)) == xSF) || \
           ((sr & (xSF | xVF)) == xVF))
#define xNGE xL
#define xNL (((sr & (xSF | xVF)) == 0) || \
            ((sr & (xSF | xVF)) == (xSF | xVF)))
#define xGE xNL

#define xLE (((sr & (xSF | xVF)) == xSF) || \
            ((sr & (xSF | xVF)) == xVF)  || xZ)
#define xNG xLE
#define xNLE ((((sr & (xSF | xVF)) == 0) || \
             ((sr & (xSF | xVF)) == (xSF | xVF))) && xNZ)
#define xG xNLE

#define H_MASK 0xFF00

#define PC 0
#define SP 1
#define SR 2
#define R2 SR
#define CG 3
#define R3 CG
#define R4 4
#define R5 5
#define R6 6
#define R7 7
#define R8 8
#define R9 9
#define R10 10
#define R11 11
#define R12 12
#define R13 13
#define R14 14
#define R15 15

#define MIN_REG 0
#define MAX_REG 15

#define pc (cpu.general[PC])
#define sp (cpu.general[SP])
#define sr (cpu.general[SR])
#define cg (cpu.general[CG])
#define r4 (cpu.general[R4])
#define r5 (cpu.general[R5])
#define r6 (cpu.general[R6])
#define r7 (cpu.general[R7])
#define r8 (cpu.general[R8])
#define r9 (cpu.general[R9])
#define r10 (cpu.general[R10])
#define r11 (cpu.general[R11])
#define r12 (cpu.general[R12])
#define r13 (cpu.general[R13])
#define r14 (cpu.general[R14])
#define r15 (cpu.general[R15])

//operand sizes
#define SIZE_BYTE 1
#define SIZE_WORD 0

void getSystemBaseTime(unsigned int *timeLow, unsigned int *timeHigh);
void getRandomBytes(void *buf, unsigned int len);

extern bool breakMode;
extern bool bugMode;
extern bool doTrace;
extern bool doTrack;
extern unsigned int randVal;

#define SYSCALL_MAGIC 0xBABE

#ifdef __IDP__
//if building an IDA plugin, then here are some defines

//various emulator related altval indicies
#define MSP430_EMU_INIT 1
#define MSP430_RANDVAL 12

#endif

void getRandomBytes(void *buf, unsigned int len);
void traceLog(char *entry);
void closeTrace();
void openTraceFile();
void setTitle();
void updateRegister(int r, unsigned int val);
void forceCode();
void codeCheck(void);
unsigned int parseNumber(char *numb);
void dumpRange();
bool isStringPointer(const char *type_str);
void skip();
void grabStackBlock();
void stepOne();
void syncDisplay();
void emuSyncDisplay();
void traceOne();
void run();
unsigned int *getRegisterPointer(unsigned int reg);
unsigned int getRegisterValue(int reg);
void setRegisterValue(int reg, unsigned int val);
void pushData();
void dumpRange(unsigned int low, unsigned int hi);
void memLoadFile(unsigned short start);
void doReset();
void jumpToCursor();
void runToCursor();
void setBreakMode(bool breakMode);
bool getBreakMode();
void setBugMode(bool track);
bool getBugMode();
void setTracking(bool track);
bool getTracking();
void setTracing(bool trace);
bool getTracing();
void setBreakpoint();
void clearBreakpoint();
void generateMemoryException();
void formatStack(unsigned int begin, unsigned int end);
bool do_getsn(bytevec_t &bv, unsigned int max, const char *console);

#ifdef __NT__
#define DIR_SEP '\\'
#define aDIR_SEP "\\"
#else
#define DIR_SEP '/'
#define aDIR_SEP "/"
#endif

#endif

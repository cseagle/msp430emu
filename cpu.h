/*
   Headers for MSP430 emulator
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

#ifndef __CPU_H
#define __CPU_H

#include "msp430defs.h"

#define CPU_VERSION VERSION(1)

struct Registers {
   unsigned int general[16];
   unsigned int initial_pc;
};

extern Registers cpu;

//masks to clear out bytes appropriate to the sizes above
extern unsigned int SIZE_MASKS[5];

//masks to clear out bytes appropriate to the sizes above
extern unsigned int SIGN_BITS[5];

//masks to clear out bytes appropriate to the sizes above
extern unsigned int CARRY_BITS[5];

extern unsigned short BITS[5];

extern unsigned int shouldBreak;

// Status codes returned by the database blob reading routine
enum {
   MSP430EMULOAD_OK,                   // state loaded ok
   MSP430EMULOAD_VERSION_INCOMPATIBLE, // incompatible version
   MSP430EMULOAD_CORRUPT,              // corrupt/truncated
   MSP430EMULOAD_UNKNOWN_HOOKFN,       // contains hook to unknown hook function
   MSP430EMULOAD_NO_NETNODE,           // no save data present
   MSP430EMUSAVE_OK,                   // state save success
   MSP430EMUSAVE_FAILED                // state save failed (buffer problems)
};

void initProgram(unsigned int entry);

void resetCpu();

void push(unsigned short val);
unsigned short pop(unsigned short size);
unsigned char readByte(unsigned short addr);
void writeByte(unsigned short addr, unsigned short val);
unsigned short readWord(unsigned short addr);
void writeWord(unsigned short addr, unsigned short val);
void writeMem(unsigned short addr, unsigned short val, unsigned short size);
unsigned short readMem(unsigned short addr, unsigned short size);

int executeInstruction();
void doInterruptReturn();

void syscall();

char *getString(unsigned short addr);

#ifdef __IDP__

int saveState(netnode &f);
int loadState(netnode &f);

#endif

#endif


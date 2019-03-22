/*
   Scripting support for the MSP430 emulator IdaPro plugin
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

#ifndef __EMU_SCRIPT_H
#define __EMU_SCRIPT_H

#define PC_REG 0
#define SP_REG 1
#define SR_REG 2
#define CG_REG 3
#define R4_REG 4
#define R5_REG 5
#define R6_REG 6
#define R7_REG 7
#define R8_REG 8
#define R9_REG 9
#define R10_REG 10
#define R11_REG 11
#define R12_REG 12
#define R13_REG 13
#define R14_REG 14
#define R15_REG 15

void register_funcs();
void unregister_funcs();

#endif

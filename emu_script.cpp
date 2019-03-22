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

#include <ida.hpp>
#include <expr.hpp>

#include "cpu.h"
#include "emu_script.h"
#include "sdk_versions.h"

#if IDA_SDK_VERSION < 520
typedef value_t idc_value_t;
#endif

#if IDA_SDK_VERSION >= 700

bool set_idc_func_ex(const char *name, idc_func_t *fp, const char *args, int extfunc_flags) {
   ext_idcfunc_t func;
   func.name = name;
   func.fptr = fp;
   func.args = args;
   func.defvals = NULL;
   func.ndefvals = 0;
   func.flags = extfunc_flags;
   return add_idc_func(func);
}

#endif

/*
 * prototypes for functions in x86emu.cpp that we use
 * to implement some of the scripted behavior
 */
void run();
void trace();
void stepOne();
void traceOne();
void emuSyncDisplay();
void setIdcRegister(unsigned int idc_reg_num, unsigned int newVal);
void addBreakpoint(unsigned int addr);

/*
 * native implementation of EmuRun.
 */
static error_t idaapi idc_emu_run(idc_value_t * /*argv*/, idc_value_t * /*res*/) {
   run();
   return eOk;
}

/*
 * native implementation of EmuStepOne.
 */
static error_t idaapi idc_emu_step(idc_value_t * /*argv*/, idc_value_t * /*res*/) {
   stepOne();
   return eOk;
}

/*
 * native implementation of EmuTraceOne.
 */
static error_t idaapi idc_emu_trace_one(idc_value_t * /*argv*/, idc_value_t * /*res*/) {
   traceOne();
   return eOk;
}

/*
 * native implementation of EmuTrace.
 */
static error_t idaapi idc_emu_trace(idc_value_t * /*argv*/, idc_value_t * /*res*/) {
   trace();
   return eOk;
}

/*
 * native implementation of EmuSync.
 */
static error_t idaapi idc_emu_sync(idc_value_t * /*argv*/, idc_value_t * /*res*/) {
   emuSyncDisplay();
   return eOk;
}

/*
 * native implementation of EmuGetReg.  Converts a register constant
 * into the appropriate offset into the cpu struct and returns the
 * value of the indicated register.  Returns -1 if an invalid register
 * number is specified.
 */
static error_t idaapi idc_emu_getreg(idc_value_t *argv, idc_value_t *res) {
   res->vtype = VT_LONG;
   if (argv[0].vtype == VT_LONG) {
      unsigned int regnum = (unsigned int)argv[0].num;
      switch (regnum) {
         case PC_REG: case SP_REG: case SR_REG: case CG_REG:
         case R4_REG: case R5_REG: case R6_REG: case R7_REG:
         case R8_REG: case R9_REG: case R10_REG: case R11_REG:
         case R12_REG: case R13_REG: case R14_REG: case R15_REG:
            res->num = cpu.general[regnum - PC_REG];
            break;
         default:
            res->num = -1;
            break;
      }
   }
   else {
      res->num = -1;
   }
   return eOk;
}

/*
 * native implementation of EmuSetReg.  Converts a register constant
 * into the appropriate offset into the cpu struct and sets the
 * value of the indicated register.  Returns 0 on success and -1 if an
 * invalid register number is specified.
 */
static error_t idaapi idc_emu_setreg(idc_value_t *argv, idc_value_t *res) {
   res->vtype = VT_LONG;
   res->num = 0;
   if (argv[0].vtype == VT_LONG && argv[1].vtype == VT_LONG) {
      unsigned int regnum = (unsigned int)argv[0].num;
      unsigned int regval = (unsigned int)argv[1].num;
      switch (regnum) {
         case PC_REG: case SP_REG: case SR_REG: case CG_REG:
         case R4_REG: case R5_REG: case R6_REG: case R7_REG:
         case R8_REG: case R9_REG: case R10_REG: case R11_REG:
         case R12_REG: case R13_REG: case R14_REG: case R15_REG:
            //these registers are all displayed so we need to update the
            //respective control as well as set the register
            setIdcRegister(regnum, regval);
            break;
         default:
            res->num = -1;
            break;
      }
   }
   else {
      res->num = -1;
   }
   return eOk;
}

/*
 * native implementation of EmuAddBpt.  Adds an emulator breakpoint
 * at the specified address.
 */
static error_t idaapi idc_emu_addbpt(idc_value_t *argv, idc_value_t *res) {
   res->vtype = VT_LONG;
   if (argv[0].vtype == VT_LONG) {
      unsigned int addr = (unsigned int)argv[0].num;
      addBreakpoint(addr);
      res->num = 1;
   }
   else {
      res->num = 0;
   }
   return eOk;
}

/*
 * Register new IDC functions for use with the emulator
 */
void register_funcs() {
   static const char idc_void[] = { 0 };
//   static const char idc_str_args[] = { VT_STR, 0 };
   static const char idc_long[] = { VT_LONG, 0 };
   static const char idc_long_long[] = { VT_LONG, VT_LONG, 0 };
#if IDA_SDK_VERSION < 570
   set_idc_func("EmuRun", idc_emu_run, idc_void);
   set_idc_func("EmuTrace", idc_emu_trace, idc_void);
   set_idc_func("EmuStepOne", idc_emu_step, idc_void);
   set_idc_func("EmuTraceOne", idc_emu_trace_one, idc_void);
   set_idc_func("EmuSync", idc_emu_sync, idc_void);
   set_idc_func("EmuGetReg", idc_emu_getreg, idc_long);
   set_idc_func("EmuSetReg", idc_emu_setreg, idc_long_long);
   set_idc_func("EmuAddBpt", idc_emu_addbpt, idc_long);
#else
   set_idc_func_ex("EmuRun", idc_emu_run, idc_void, EXTFUN_BASE);
   set_idc_func_ex("EmuTrace", idc_emu_trace, idc_void, EXTFUN_BASE);
   set_idc_func_ex("EmuStepOne", idc_emu_step, idc_void, EXTFUN_BASE);
   set_idc_func_ex("EmuTraceOne", idc_emu_trace_one, idc_void, EXTFUN_BASE);
   set_idc_func_ex("EmuSync", idc_emu_sync, idc_void, EXTFUN_BASE);
   set_idc_func_ex("EmuGetReg", idc_emu_getreg, idc_long, EXTFUN_BASE);
   set_idc_func_ex("EmuSetReg", idc_emu_setreg, idc_long_long, EXTFUN_BASE);
   set_idc_func_ex("EmuAddBpt", idc_emu_addbpt, idc_long, EXTFUN_BASE);
#endif
}

/*
 * Unregister IDC functions when the plugin is unloaded
 */
void unregister_funcs() {
#if IDA_SDK_VERSION < 570
   set_idc_func("EmuRun", NULL, NULL);
   set_idc_func("EmuTrace", NULL, NULL);
   set_idc_func("EmuStepOne", NULL, NULL);
   set_idc_func("EmuTraceOne", NULL, NULL);
   set_idc_func("EmuSync", NULL, NULL);
   set_idc_func("EmuGetReg", NULL, NULL);
   set_idc_func("EmuSetReg", NULL, NULL);
   set_idc_func("EmuAddBpt", NULL, NULL);
#else
   set_idc_func_ex("EmuRun", NULL, NULL, 0);
   set_idc_func_ex("EmuTrace", NULL, NULL, 0);
   set_idc_func_ex("EmuStepOne", NULL, NULL, 0);
   set_idc_func_ex("EmuTraceOne", NULL, NULL, 0);
   set_idc_func_ex("EmuSync", NULL, NULL, 0);
   set_idc_func_ex("EmuGetReg", NULL, NULL, 0);
   set_idc_func_ex("EmuSetReg", NULL, NULL, 0);
   set_idc_func_ex("EmuAddBpt", NULL, NULL, 0);
#endif
}

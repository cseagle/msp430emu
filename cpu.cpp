/*
   Source for MSP430 emulator
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

#include <stdio.h>

#include "buffer.h"
#include "cpu.h"
#include "msp430emu_ui.h"

//masks to clear out bytes appropriate to the sizes above
unsigned int SIZE_MASKS[] = {0x0000FFFF, 0x000000FF};

//masks to limit bit rotation amount in rotation instructions
unsigned int ROTATE_SIZE_MASKS[] = {0xF, 7};

//masks to clear out bytes appropriate to the sizes above
unsigned int SIGN_BITS[] = {0x00008000, 0x00000080};

//masks to clear out bytes appropriate to the sizes above
unsigned int CARRY_BITS[] = {0x00010000, 0x00000100};

#define SREG(x) (((x) >> 8) & 0xf)
#define DREG(x) ((x) & 0xf)
#define AD(x) (((x) >> 7) & 1)
#define BW(x) (((x) >> 6) & 1)
#define AS(x) (((x) & 0x30) >> 4)
#define COND(x) (((x) >> 10) & 7)
#define OFFSET(x) (((x) & 0x3ff) * 2)

//The cpu
Registers cpu;

static qstring console;
bool breakMode = false;

static unsigned int instStart;
static unsigned short opcode;   //opcode, first or second byte (if first == 0x0F)
static unsigned short sreg;
static unsigned short dreg;
static unsigned short a_s;
static unsigned short a_d;
static unsigned short b_w;
static unsigned int sourceOp;
static unsigned int destOp;

void getDest(unsigned short mode, unsigned short reg);
void getSource(unsigned short mode, unsigned short reg);
void putDest(unsigned short mode, unsigned short reg, unsigned short val);

//flag to tell CPU users that they should probably break because something
//strange has happened
unsigned int shouldBreak = 1;

void setBreakMode(bool newMode) {
   breakMode = newMode;
}

bool getBreakMode() {
   return breakMode;
}

#ifdef __IDP__

int saveState(netnode &f) {
   unsigned char *buf = NULL;
   unsigned int sz;
//   Buffer b(CPU_VERSION);
   Buffer b;

   //need to start writing version magic as first 4 bytes
   //current registers for active thread are saved here
   b.write((char*)cpu.general, sizeof(cpu.general));
   b.write((char*)&cpu.initial_pc, sizeof(cpu.initial_pc));

   if (!b.has_error()) {
   //
      // Delete any previous blob data in the IDA database node.
      //
      f.delblob(0, 'B');

      //
      // Convert the output blob object into a buffer and
      // store it in the database node.
      //
      sz = b.get_wlen();
   //   msg("msp430emu: writing blob of size %d.\n", sz);
      buf = b.get_buf();
/*
      for (int i = 0; i < sz; i += 16) {
         for (int j = 0; j < 16 && (j + i) < sz; j++) {
            msg("%2.2X ", buf[i + j]);
         }
         msg("\n");
      }
*/
      f.setblob(buf, sz, 0, 'B');
      return MSP430EMUSAVE_OK;
   }
   else {
      return MSP430EMUSAVE_FAILED;
   }
}

int loadState(netnode &f) {
   unsigned char *buf = NULL;
   size_t sz;
//   int personality = f.altval(HEAP_PERSONALITY);
   // Fetch the blob attached to the node.
   if ((buf = (unsigned char *)f.getblob(NULL, &sz, 0, 'B')) == NULL) return MSP430EMULOAD_NO_NETNODE;
//   msg("msp430emu: netnode found, sz = %d.\n", sz);
/*
   msg("netnode found, sz = %d.\n", sz);
   for (int i = 0; i < sz; i += 16) {
      for (int j = 0; j < 16 && (j + i) < sz; j++) {
         msg("%2.2X ", buf[i + j]);
      }
      msg("\n");
   }
*/
   Buffer b(buf, sz);
   //need to read version magic as first 4 bytes and skip stages depending on version
   b.read((char*)cpu.general, sizeof(cpu.general));
   b.read((char*)&cpu.initial_pc, sizeof(cpu.initial_pc));

   qfree(buf);

   return b.has_error() ? MSP430EMULOAD_CORRUPT : MSP430EMULOAD_OK;
}

#endif

static bool offMessage = false;

void resetCpu() {
   memset(cpu.general, 0, sizeof(cpu.general));
   pc = readWord(0xfffe);
   //enable interrupts by default per Kris Kaspersky
   sr = 0;
   offMessage = false;
}

void initProgram(unsigned int entry) {
   pc = entry;
}

//sign extension functions
//byte->unsigned short
unsigned short sebw(unsigned short val) {
   short result = (char)val;
   return (unsigned short) result;
}

//return a byte
unsigned char readByte(unsigned short addr) {
   return get_byte(addr);
}

//don't interface to IDA's get_word/long routines so
//that we can detect stack usage in readByte
unsigned short readWord(unsigned short addr) {
   if (addr & 1) {
      msg("Misaligned read from address 0x%04x\n", addr);
      return 0;
   }
   else {
      unsigned short result = readByte(addr + 1);
      result <<= 8;
      return result | readByte(addr);
   }
}

//all reads from memory should be through this function
unsigned short readMem(unsigned short addr, unsigned short size) {
   unsigned short result = 0;
   switch (size) {
      case SIZE_BYTE:
         result = readByte(addr);
         break;
      case SIZE_WORD:
         result = readWord(addr);
         break;
   }
   return result;
}

unsigned int readBuffer(unsigned short addr, void *buf, unsigned int nbytes) {
//   int result = 0;
   for (unsigned int i = 0; i < nbytes; i++) {
      ((unsigned char*)buf)[i] = readByte(addr + i);
   }
   return nbytes;
}

//store a byte
void writeByte(unsigned short addr, unsigned short val) {
   patch_byte(addr, val);
}

//don't interface to IDA's put_word/long routines so
//that we can detect stack usage in writeByte
void writeWord(unsigned short addr, unsigned short val) {
   if (addr & 1) {
      msg("Misaligned write to address 0x%04x\n", addr);
   }
   else {
      writeByte(addr, val);
      writeByte(addr + 1, val >> 8);
   }
}

//all writes to memory should be through this function
void writeMem(unsigned short addr, unsigned short val, unsigned short size) {
   switch (size) {
      case SIZE_BYTE:
         writeByte(addr, val);
         break;
      case SIZE_WORD:
         writeWord(addr, val);
         break;
   }
}

unsigned int writeBuffer(unsigned short addr, void *buf, unsigned int nbytes) {
//   int result = 0;
   for (unsigned int i = 0; i < nbytes; i++) {
      writeByte(addr + i, ((unsigned char*)buf)[i]);
   }
   return nbytes;
}

void push(unsigned short val) {
   sp -= 2;
   writeMem(sp, val, SIZE_WORD);
}

unsigned short pop() {
   unsigned short res = readMem(sp, SIZE_WORD);
   sp += 2;
   return res;
}

//read according to specified n from eip location
unsigned short fetch() {
   unsigned short op = readWord(pc);
   pc += 2;
//   msg(" 0x%04x", op);
   return op;
}

//deal with sign, zero, and parity flags
void setSR(unsigned int val) {
   val &= SIZE_MASKS[b_w]; //mask off upper bytes
   if (val) CLEAR(xZF);
   else SET(xZF);
   if (val & SIGN_BITS[b_w]) SET(xSF);
   else CLEAR(xSF);
   sr &= 0x1F;
}

void checkAddOverflow(unsigned int op1, unsigned int op2, unsigned int sum) {
   unsigned int mask = SIGN_BITS[b_w];
   if ((op1 & op2 & ~sum & mask) || (~op1 & ~op2 & sum & mask)) SET(xVF);
   else CLEAR(xVF);
}

void checkSubOverflow(unsigned int op1, unsigned int op2, unsigned int diff) {
   unsigned int mask = SIGN_BITS[b_w];
   if ((op1 & ~op2 & ~diff & mask) || (~op1 & op2 & diff & mask)) SET(xVF);
   else CLEAR(xVF);
}

//handle instructions that begin w/ 0x1n
int doOne() {
   switch ((opcode >> 6) & 0xf) {
      case 0: case 1: { //rrc rrc.b
         getDest(a_s, dreg);
         unsigned int c = destOp & 1;
         CLEAR(xVF);
         destOp >>= 1;
         if (xC) {
            destOp |= SIGN_BITS[b_w];
         }
         c ? SET(xCF) : CLEAR(xCF);
            
         if (!bugMode) {
            setSR(destOp);
         }
         else {
            //microcorruption fails to set/clear ZF according to result
            //microcorruption fails to clear SF according to result
            if (destOp & SIGN_BITS[b_w]) SET(xSF);
         }
         putDest(a_s, dreg, destOp);
         break;
      }
      case 2:  //swapb
         getDest(a_s, dreg);
         destOp = (destOp >> 8) | (destOp << 8);
         putDest(a_s, dreg, destOp);
         break;
      case 4: case 5: { //rra rra.b
         getDest(a_s, dreg);

         if (!bugMode) {
               //microcorruption system does not copy low bit to carry
            unsigned int c = destOp & 1;
            c ? SET(xCF) : CLEAR(xCF);
         }
         unsigned int s = destOp & SIGN_BITS[b_w];
         CLEAR(xVF);
         destOp >>= 1;
         if (s) destOp |= s;

         if (!bugMode) {
            setSR(destOp);
         }
         else {
            //microcorruption fails to set/clear ZF according to result
            //microcorruption fails to clear SF according to result
            if (destOp & SIGN_BITS[b_w]) SET(xSF);
         }

         putDest(a_s, dreg, destOp);
         break;
      }
      case 6:   //sxtb
         getDest(a_s, dreg);
         destOp = sebw(destOp);
         destOp ? SET(xCF) : CLEAR(xCF);
         setSR(destOp);
         CLEAR(xVF);
         putDest(a_s, dreg, destOp);
         break;
      case 8: case 9:  //push push.b
         getSource(a_s, dreg);
         push(sourceOp);
         break;
      case 10:   //call
         getSource(a_s, dreg);
         push(pc);
         pc = sourceOp;
         break;
      case 12:
         sr = pop();
         pc = pop();
         break;
      default:
         return 0;
   }
   return 1;
}

//handle instructions that begin w/ 0x2n
int doJump(unsigned int cond, unsigned int offset) {
   unsigned short delta = 0;
   switch (cond) {
      case 0:  // jne/jnz
         if (!xZ) delta = offset;
         break;
      case 1:  // jeq/jz
         if (xZ) delta = offset;
         break;
      case 2:  // jnc
         if (!xC) delta = offset;
         break;
      case 3:  // jc
         if (xC) delta = offset;
         break;
      case 4:  // jn
         if (xS) delta = offset;
         break;
      case 5: { // jge
         unsigned short f = xV | xS;
         if (f == 0 || f == (xVF | xSF)) delta = offset;
         break;
      }
      case 6: { // jl
         unsigned short f = xV | xS;
         if (f == xVF || f == xSF) delta = offset;
         break;
      }
      case 7:  // jmp
         delta = offset;
         break;
   }
   pc += delta;
   return 1;
}

//handle instructions that begin w/ 0x4n
int doMove() {  //MOV.B, MOV
   putDest(a_d, dreg, sourceOp);
   return 1;
}

//handle instructions that begin w/ 0x6n
int doAdd(unsigned short carryIn) {  //ADD.B ADD ADDC.B ADDC
   getDest(a_d, dreg);
   unsigned int res = destOp + sourceOp + carryIn;
   if (res & CARRY_BITS[b_w]) SET(xCF);
   else CLEAR(xCF);
   checkAddOverflow(destOp, sourceOp, res);
   setSR(res);
   putDest(a_d, dreg, res);
   return 1;
}

//handle instructions that begin w/ 0x7n
int doSub(unsigned short carryIn) {   //SUB.B SUB SUBC.B SUBC 
   getDest(a_d, dreg);
   unsigned int res = destOp + (0xffff & ~sourceOp) + carryIn;
   if (res & CARRY_BITS[b_w]) SET(xCF);
   else CLEAR(xCF);
   checkSubOverflow(destOp, sourceOp, res);
   setSR(res);
   putDest(a_d, dreg, res);
   return 1;
}

//handle instructions that begin w/ 0x9n
int doCmp() {     //CMP  CMP.B
   getDest(a_d, dreg);
   unsigned int res = destOp + (0xffff & ~sourceOp) + 1;
   if (res & CARRY_BITS[b_w]) SET(xCF);
   else CLEAR(xCF);
   checkSubOverflow(destOp, sourceOp, res);
   setSR(res);
   return 1;
}

//add low nibble of a and b in MSP430 BCD manner
unsigned int bcdAddDigit(unsigned int a, unsigned int b, unsigned int c = 0) {
   unsigned int res = (a & 0xf) + (b & 0xf) + (c & 1);  //c is carry
   c = 0;
   if (res > 9) {
      c = 0x10;
      res = (res - 10) & 0xf;
   }
   return c | res;
}

//handle instructions that begin w/ 0xAn
int doDadd() {          //DADD,  DADD.B
   unsigned int res;
   getDest(a_d, dreg);
   
   //reference manual says C flag is added in here, but microcorruption 
   //is not reflecting that behavior
   if (!bugMode) {
      res = (sourceOp & 0xf) + (destOp & 0xf) + xC;
   }
   else {
      res = bcdAddDigit(sourceOp, destOp);
   }
   unsigned int c = res >> 4;
   res = (res & 0xf) + (bcdAddDigit(sourceOp  >> 4, destOp >> 4, c) << 4);
   c = res >> 8;
   if (!b_w) {
      res = (res & 0xff) + (bcdAddDigit(sourceOp  >> 8, destOp >> 8, c) << 8);
      c = res >> 12;
      res = (res & 0xfff) + (bcdAddDigit(sourceOp  >> 12, destOp >> 12, c) << 12);
      c = res >> 16;
   }
   c ? SET(xCF) : CLEAR(xCF);

   if (!bugMode) {
      setSR(destOp);
   }
   else {
      //microcorruption simulator fails to set/clear flags other than CF according to result
   }

   putDest(a_d, dreg, res);
   return 1;
}

//handle instructions that begin w/ 0xBn
int doBit() {     //BIT.B  BIT
   getDest(a_d, dreg);
   unsigned int res = destOp & sourceOp;
   CLEAR(xVF);
   res ? SET(xCF) : CLEAR(xCF); 
   setSR(res);
   return 1;
}

//handle instructions that begin w/ 0xCn
int doBic() {    //BIC.B  BIC
   getDest(a_d, dreg);
   unsigned int res = destOp & ~sourceOp;
   putDest(a_d, dreg, res);
   return 1;
}

//handle instructions that begin w/ 0xDn
int doBis() {     //BIS.B   BIS
   getDest(a_d, dreg);
   unsigned int res = destOp | sourceOp;
   putDest(a_d, dreg, res);
   return 1;
}

//handle instructions that begin w/ 0xEn
int doXor() {   // XOR.B   XOR
   getDest(a_d, dreg);
   unsigned int res = destOp ^ sourceOp;
   (destOp & sourceOp & SIGN_BITS[b_w]) ? SET(xVF) : CLEAR(xVF);
   res ? SET(xCF) : CLEAR(xCF); 
   setSR(res);
   putDest(a_d, dreg, res);
   return 1;
}

//handle instructions that begin w/ 0xFn
int doAnd() {    //AND    AND.B
   getDest(a_d, dreg);
   unsigned int res = destOp & sourceOp;
   CLEAR(xVF);
   res ? SET(xCF) : CLEAR(xCF); 
   setSR(res);
   putDest(a_d, dreg, res);
   return 1;
}

/*
 * Build an ascii C string by reading directly from the database
 * until a NULL is encountered.  Returned value must be free'd
 */

char *getString(unsigned short addr) {
   int size = 16;
   int i = 0;
   unsigned char *str = NULL, ch;
   str = (unsigned char*) malloc(size);
   if (addr) {
      while ((ch = get_byte(addr++)) != 0) {
         if (i == size) {
            str = (unsigned char*)realloc(str, size + 16);
            size += 16;
         }
         if (ch == 0xFF) break;  //should be ascii, something wrong here
         str[i++] = ch;
      }
      if (i == size) {
         str = (unsigned char*)realloc(str, size + 1);
      }
   }
   str[i] = 0;
   return (char*)str;
}

void syscall() {
   unsigned short syscallNum = (sr >> 8) & 0x7f;
   //args at sp+6
   switch (syscallNum) {
      case 0: {
         unsigned short ch = readWord(sp + 8);
         console += (char)ch;
         msg("%c", ch);
         break;
      }
      case 1:
         //open some kind of input dialog
         msg("getchar invoked, please set R15\n");
         break;
      case 2: {
         bytevec_t bv;
         //always break following send or wait
         shouldBreak = 1;
         unsigned short addr = readWord(sp + 8);
         unsigned short len = readWord(sp + 10);
//         msg("gets(0x%x, %d)\n", addr, len);
         if (do_getsn(bv, len, console.c_str())) {
            for (bytevec_t::iterator i = bv.begin(); i != bv.end(); i++) {
               patch_byte(addr++, *i);
            }
         }
         else {
            //return without poping ret so that the syscall gets rerun
            return;
         }
         break;
      }
      case 0x10:
         msg("DEP is on\n");
         break;
      case 0x11:
         if (readWord(sp + 10)) {
            msg("Marking page 0x%x writable\n", readWord(sp + 8));
         }
         else {
            msg("Marking page 0x%x executable\n", readWord(sp + 8));
         }
         break;
      case 0x20:
//         msg("rand\n");
         r15 = 0x1234;
         break;
      case 0x7d: {
         unsigned short addr = readWord(sp + 10);
         unsigned short pw = readWord(sp + 8);
         char *str = getString(pw);
//         msg("hsm1, %s/0x%x\n", str, addr);
         free(str);
         break;
      }
      case 0x7e: {
         unsigned short pw = readWord(sp + 8);
         char *str = getString(pw);
//         msg("hsm2, %s\n", str);
         free(str);
         break;
      }
      case 0x7f:
         restoreCursor();
         warning("The lock is now open!\n");
         msg("The lock is now open!\n");
         showWaitCursor();
        //always break after lock gets opened
         shouldBreak = 1;
         break;
   }
   if (breakMode) {
      shouldBreak = 1;
   }
   pc = pop();
}

void getDest(unsigned short mode, unsigned short reg) {
//   msg("getDest: mode - %d, reg - %d\n", mode, reg);
   switch (mode) {
      case 0:  //register mode
         destOp = b_w ? cpu.general[reg] & 0xff : cpu.general[reg];
         break;
      case 1:  //
         switch (reg) {
            case PC: {
               unsigned short pc_now = pc;
               unsigned short y = fetch();
               destOp = readMem(pc_now + y, b_w);
               break;
            }
            case R2:
               destOp = readMem(fetch(), b_w); //CG1
               break;
            default: {
               unsigned short n = fetch();
               destOp = readMem(cpu.general[reg] + n, b_w);
               break;
            }
         }
         break;
      case 2:   //indirect register mode
         //invalid destination mode
         break;
      case 3: //indirect autoincrement
         //invalid destination mode
         break;
   }
}

void getSource(unsigned short mode, unsigned short reg) {
//   msg("getSource: sreg %d, dreg, %d, b/w: %d, As: %d, Ad: %d\n", sreg, dreg, b_w, a_s, a_d);
//   msg("getSource: mode %d, reg, %d\n", mode, reg);
   switch (mode) {
      case 0:  //register mode
         if (reg == R3) {
            sourceOp = 0; //CG2
         }
         else {
            sourceOp = b_w ? cpu.general[reg] & 0xff : cpu.general[reg];
         }
         break;
      case 1:  //
         switch (reg) {
            case PC: {
               unsigned short pc_now = pc;
               unsigned short x = fetch();
               sourceOp = readMem(pc_now + x, b_w);
               break;
            }
            case R2:
               sourceOp = readMem(fetch(), b_w); //CG1
               break;
            case R3:
               sourceOp = 1; //CG2
               break;
            default: {
               unsigned short n = fetch();
               sourceOp = readMem(cpu.general[reg] + n, b_w);
               break;
            }
         }
         break;
      case 2:   //indirect register mode
         switch (reg) {
            case R2:
               sourceOp = 4; //CG1
               break;
            case R3:
               sourceOp = 2; //CG2
               break;
            default:
               sourceOp = readMem(cpu.general[reg], b_w);
               break;
         }
         break;
      case 3: //indirect autoincrement
         switch (reg) {
            case PC:
               sourceOp = fetch();
               break;
            case R2:
               sourceOp = 8; //CG1
               break;
            case R3:
               sourceOp = 0xffff; //CG2
               break;
            default:
               sourceOp = readMem(cpu.general[reg], b_w);
               if (b_w && (reg != SP)) {
                  cpu.general[reg]++;
               }
               else {
                  cpu.general[reg] += 2;
               }
               break;
         }
         break;
   }
}

void putDest(unsigned short mode, unsigned short reg, unsigned short val) {
//   msg("putDest: mode %d, reg, %d, b/w: %d\n", mode, reg, b_w);
   if (b_w) {
      val = val & 0xff;
   }
   switch (mode) {
      case 0:  //register mode
         cpu.general[reg] = val;
         break;
      case 1:  //
         switch (reg) {
            case PC: {
               unsigned short pc_now = pc;
               unsigned short x = fetch();
               writeMem(pc_now + x, val, b_w);
               break;
            }
            case R2:
               writeMem(fetch(), val, b_w); //CG1
               break;
            default: {
               unsigned short n = fetch();
               writeMem(cpu.general[reg] + n, val, b_w);
               break;
            }
         }
         break;
      case 2:   //indirect register mode
         //invalid destination mode
         break;
      case 3: //indirect autoincrement
         //invalid destination mode
         break;
   }
}

int executeInstruction() {
   pc = pc & 0xffff;
   instStart = pc;
   cpu.initial_pc = pc;
 
   if (sr & 0x10) {
      //the cpu is off
      if (!offMessage) {
         offMessage = true;
         warning("The cpu has been powered off.");
         msg("The cpu has been powered off.\n");
      }
      return 0;
   }
   
//   msg("\n0x%04x: ", pc);
   
//msg("msp430emu: begin instruction, pc: 0x%x\n", pc);
   if (pc & 1) {
      msg("Misaligned instruction 0x%04x\n", pc);
   }
   else if (pc == 0x10) {
      syscall();
   }
   else {
      unsigned int res = 0;
      opcode = fetch();
      unsigned short op = opcode >> 12;
      a_s = AS(opcode);
      dreg = DREG(opcode);
      if (op >= 4) {
         //decode format 1 instruction
         sreg = SREG(opcode);
         b_w = BW(opcode);
         a_d = AD(opcode);
         getSource(a_s, sreg);
      }
      switch (op) {
         case 1:
            if ((opcode & 0xc00) == 0) {
               res = doOne();
            }
            break;
         case 2: case 3: {
            unsigned short offs = OFFSET(opcode);
            if (offs & 0x400) {
               offs |= 0xF800;
            }
            res = doJump(COND(opcode), offs);
            break;
         }
         case 4:
            res = doMove();
            break;
         case 5:
            res = doAdd(0);
            break;
         case 6:
            res = doAdd(xC);
            break;
         case 7:
            res = doSub(xC);
            break;
         case 8:
            res = doSub(1);
            break;
         case 9:
            res = doCmp();
            break;
         case 10:
            res = doDadd();
            break;
         case 11:
            res = doBit();
            break;
         case 12:
            res = doBic();
            break;
         case 13:
            res = doBis();
            break;
         case 14:
            res = doXor();
            break;
         case 15:
            res = doAnd();
            break;
      }
      if (res == 0) {
         msg("Invalid instruction 0x%04x, at address 0x%04x\n", opcode, instStart);
      }      
   }
//msg("msp430emu: end instruction, eip: 0x%x\n", eip);
   pc = pc & 0xffff;
   return 0;
}


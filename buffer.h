/*
   Source for MSP430 emulator IdaPro plugin
   File: buffer.h
   Copyright (c) 2005-2010 Chris Eagle
   
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

#ifndef __BUFFER_H
#define __BUFFER_H

#define BUFFER_MAGIC 0x861DA000
#define BUFFER_MAGIC_MASK 0xFFFFF000
#define VERSION(n) (BUFFER_MAGIC | n)

class Buffer {
public:
   Buffer();
   Buffer(unsigned int magic);
   Buffer(unsigned char *buf, unsigned int len);
   ~Buffer();
   
   int read(void *data, unsigned int len);
   bool rewind(unsigned int amt);
   int write(const void *data, unsigned int len);
   int readString(char **str);
   int writeString(const char *str);
   
   unsigned char *get_buf();
   unsigned int get_wlen();
   unsigned int get_rlen();
   bool has_error() {return error;};
   void reset_error() {error = false;};
   unsigned int getMagic() {return magic;};
   unsigned int getVersion();

private:
   Buffer(const Buffer & /*b*/) {};
   int check_size(unsigned int max);
   void init(unsigned int size);
   
   unsigned int magic;
   unsigned char *bptr;
   unsigned int rptr;
   unsigned int wptr;
   unsigned int sz;
   bool error;
};

#endif


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

#ifndef __MSP430EMU_UI_H
#define __MSP430EMU_UI_H

void setEmulatorTitle(const char *title);
void updateRegisterDisplay(int r);
bool createEmulatorWindow();
void destroyEmulatorWindow();
void displayEmulatorWindow();
char *inputBox(const char *boxTitle, const char *msg, const char *init);
char *getOpenFileName(const char *title, char *fileName, int nameLen, const char *filter, char *initDir = 0);
char *getSaveFileName(const char *title, char *fileName, int nameSize, const char *filter);
char *getDirectoryName(const char *title, char *dirName, int nameSize);
void showErrorMessage(const char *msg);
void showInformationMessage(const char *title, const char *msg);
void showWaitCursor();
void restoreCursor();

#endif


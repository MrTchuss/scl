/** 
  SCL - ShellCode Loader. Execute locally, display, and validate shellcodes
  Copyright (C) 2011 - buffer (bufferoverfl0wz at google mail)

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  This should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
 
#ifndef args_h
#define args_h

extern const char *displayDefault; // = "\\x";

typedef struct {
   int ffileName;
   char const *fileName;
   int fexecute;
   int fsize;
   int size;
   int fpad;
   int pad;
   int fdisplay;
   char const *display;
   int fret;
   char const *ret;
   int fbadchar;
   char const *badchar;
} Flags;

extern int getArgs(int argc, char **argv, Flags *flags);

#endif


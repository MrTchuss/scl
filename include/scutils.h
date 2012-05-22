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
 
#ifndef scutils_h
#define scutils_h

#include <stdlib.h>
#include <stdio.h>

/**
 * Helper to open file
 */
#define OPEN(fd, fileName, flags, mode) if( ((fd) = open((fileName), (flags), (mode))) == -1 ) \
{ \
   fprintf(stderr, "Cannot open %s\n", fileName);\
   return -1;\
}
#define FOPEN(fdesc, fileName, mode) if( ((fdesc) = fopen((fileName), (mode))) == NULL ) \
{ \
   fprintf(stderr, "Cannot open %s\n", fileName);\
   return -1;\
}

typedef enum {
   INFO,
   WARNING,
   ERROR,
   FATAL
} InfoLevel;

typedef enum {ASLR_ON,
              ASLR_OFF,
              ASLR_UNKNOWN} AslrState;

typedef char ShellCodeByte;

typedef struct {
   ShellCodeByte *code;
   size_t size;
} ShellCode;

   
/* strings helpers*/
/*extern char *hex(char c, char *out);
extern char *safe_copy(char *destination, const char *source, size_t num);*/
extern void *incmemcpy(char **dest, const void *src, size_t num);
extern void *incmemset(char **dest, char c, size_t num);

/* General purpose shellcoding helpers  */
//extern AslrState isAslr();
//extern void *getEsp();

/**
 * Find the address of an environement variable
 * @param[in] eggName name of the environement variable to look for
 * @param[in] callerName name of this application (typically argv[0])
 * @param[in] targetName name of the target to exploit
 * @return address of the environement variable
 */
//extern void *findEgg(const char *eggName, const char *callerName, const char *targetName);

/**
 * Display locations where an opcode is found
 * @param[in] start memory start
 * @param[in] memory stop
 * @param[in] opcode hexaopcode
 * @param[in] asmOpcode asm opcode
 */
/*extern void search(const void *start, const void *stop, const char *opcode, const char *asmOpcode);*/

extern int isHexa(char const *const value);

/*extern int str2hex(char const *const value, ShellCode *out);*/

extern void info(const char *msg, InfoLevel infoLevel);

#endif


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
 
#ifndef sc_h
#define sc_h

#include "scutils.h"
/*extern int stringOnStack(const char *const str, char **out);*/

/**
 * Execute a shellcode in standalone
 * mode for validation.
 * @param[in] sc shellcode to execute
 * @return 0 on success.
 */
extern int sctest(ShellCode sc);

/**
 * Reads shellcode from a binary file and store it into a char*
 * @param[in] fileName name of the file from which the shellcode should be read
 * @param[out] sc shellcode. MUST BE FREED BY USER invoking screlease
 */
extern int scload(const char *fileName, ShellCode *sc);

/**
 * Reads shellcode from a binary file and store it into a char*
 * @param[in] shellcode to remove
 */
extern int screlease(ShellCode *sc);

/**
 * Pad the shell code with NOP before, and after if after is 
 * greater than 0.
 * WARNING: an extra 4 bytes is added to overwrite EBP. These bytes are loaded with NOPs
 * @param[in, out] sc shellcode to pad. MUST BE FREED BY USER !
 * @param[in] totalSize the total size the shellcode must have
 * @param[in] after the number of bytes that must be after the shellcode (before eip)
 * @return 0 on success.
 */
extern int scpad(ShellCode *sc, size_t newSize, size_t padding);

/**
 * Prepare the shellcode as a string to exploit with another tool.
 * The shellcode is translated to hexa string. Every two characters (so 
 * every bytes), a special character can be added. Depending on the tool
 * that will be use for exploitation, can be %, \x ...
 * @param[in] sc shellcode to translate
 * @param[in] hexHeader a string that will prefix every bytes
 * @param[out] scHex the shellcode in hexa string. MUST BE FREED BY USER !
 * @return 0 on sucess
 */
extern int sc2hex(const ShellCode sc, const char *hexHeader, char **scString);

extern int hex2sc(ShellCode *sc, const char *hexHeader, const char *scHex);

extern int sccheckbadchar(const char const *badchar, const ShellCode sc);


#endif


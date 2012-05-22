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
 
#include <scutils.h>

#include <errno.h>
#include <string.h>

int isHexa(char const *const value)
{
   char const *ptr;
   for( ptr = value ; *ptr != '\0' ; ++ ptr )
   {
      if( (*ptr < 0x30 || *ptr > 0x39) &&
          (*ptr < 0x41 || *ptr > 0x46) &&
          (*ptr < 0x61 || *ptr > 0x66) )
      {
         return EXIT_FAILURE;
      }
   }
   return EXIT_SUCCESS;
}

void *incmemcpy(char **dest, const void *src, size_t num)
{
   memcpy(*dest, src, num);
   *dest+=num;
   return *dest;
}

void *incmemset(char **dest, char c, size_t num)
{
   memset(*dest, c, num);
   *dest += num;
   return *dest;
}

void info(const char *msg, InfoLevel infoLevel)
{
   printf("%s %s\n", "-I-", msg);
}


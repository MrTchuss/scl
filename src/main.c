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
 
#include <sc.h>
#include <args.h>

int main(int argc, char **argv)
{
   Flags flags;
   ShellCode sc;
   char *scHex = NULL;
   int rslt, padSize;

   getArgs(argc, argv, &flags);

   if( 1 == flags.ffileName )
   {
      puts("Loading shellcode data...");
      rslt = scload(flags.fileName, &sc);
      if( EXIT_SUCCESS != rslt )
      {
         puts("ERROR");
         return EXIT_FAILURE;
      }
   }

   if( 1 == flags.fbadchar )
   {
      rslt = sccheckbadchar(flags.badchar, sc);
      if( EXIT_SUCCESS != rslt )
      {
         puts("[!] Found bad char in shellcode. Please fix.");
         return EXIT_FAILURE;
      }
   }

   if( 1 == flags.fsize )
   {
      padSize = 0;
      if( 1 == flags.fpad )
      {
         padSize = flags.pad;
      }
      puts("Padding");
      scpad(&sc, flags.size, padSize);
   }
   
   /*if( 1 == flags.fret )
   {
      puts("Appending ret address.");
      rslt = scret(&sc, flags.ret);
      if( EXIT_SUCCESS != rslt )
      {
         puts("ERROR IN APPENDING RET ADDR");
         return EXIT_FAILURE;
      }
   }*/
   
   if( 1 == flags.fdisplay )
   {
      puts("Conversion to binary");
      rslt = sc2hex(sc, flags.display, &scHex);
      if( EXIT_SUCCESS != rslt )
      {
         puts("ERROR IN HEX CONVERSION");
         return EXIT_FAILURE;
      }
      puts(scHex);
   }
   
   if( 1 == flags.fexecute )
   {
      puts("Testing shellcode");
      sctest(sc);
   }

   if( NULL != scHex )
      free(scHex);

   //screlease(&sc);

   return EXIT_SUCCESS;
}


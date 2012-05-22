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
 
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <args.h>
#include <scutils.h>

const char *displayDefault = "\\x";

void abort_(char *const msg)
{
   fprintf(stderr, msg);
   exit(EXIT_FAILURE);
}

void help()
{
   puts("SCL - ShellCode Loader.\n      Execute locally, display, and validate shellcodes\n\n"
        "Options:\n--------\n"
        "   -l <filename> loads shellcode from binary file\n"
        "   -x            execute the shell code\n"
        "   -s <size>     total size of shellcode. Will prepend NOPs\n"
        "   -p <size>     pad shellcode with NOPs. WARNING This will counted in the total amount of data\n"
        "   -d [<sep>]    display built shellcode with sep as separator. If not specified, the separator is %\n"
        //"   -r <addr>     append the return address of the shell code. By default, there is no return address\n"
        "   -b <badchars> returns is any bad char is found in shellcode. Badchars are a list of bytecode forbidden (e.g. -b 000A0D)\n"
        "   -h            prompt this message\n"
        "\n");
}

int checkArgs(Flags flags)
{
   /*if( 1 == flags.fret )
   {
      if( 1 != flags.ffileName ) // no ShellCode loaded
      {
         abort_("[!] You must define a shellcode file before resizing it\n");
      }
      if( 8 != strlen(flags.ret) )
      {
         abort_("[!] Return address must be exactly 4 bytes (eight characters)");
      }
      // check the char set for ret:
      if( EXIT_FAILURE == isHexa(flags.ret) )
      {
         abort_("[!] Return address must be hexadecimal format\n");
      }
   }*/
   if( 1 == flags.fbadchar )
   {
      if( 0 != ( strlen(flags.badchar) % 2 ) )
      {
         abort_("[!] Bad chars must be encoded in two digits modes\n");
      }
      if( EXIT_FAILURE == isHexa(flags.badchar) )
      {
         abort_("[!] Bad chars must be encoded in hexa format\n");
      }
   }
   if( 1 == flags.fsize )
   {
      if( 1 != flags.ffileName ) // no ShellCode loaded
      {
         abort_("[!] You must define a shellcode file before resizing it\n");
      }
   }
   if( 1 == flags.fpad )
   {
      if( 1 != flags.fsize )
      {
         abort_("[!] You must define shellcode size before padding it.\n");
      }
   }
   if( 1 == flags.fdisplay )
   {
      if( 1 != flags.ffileName ) // no ShellCode loaded
      {
         abort_("[!] You must define a shellcode file before displaying it\n");
      }
   }
   if( 1 == flags.fexecute )
   {
      if( 1 != flags.ffileName ) // no ShellCode loaded
      {
         abort_("[!] You must define a shellcode file before executing it\n");
      }
   }
   return EXIT_SUCCESS;
}


int getArgs(int argc, char **argv, Flags *flags)
{
   int opt;
   /*while( -1 != (opt = getopt(argc, argv, "l:xs:p:d::hr:") ) )*/
   while( -1 != (opt = getopt(argc, argv, "l:xs:p:d::hb:") ) )
   {
      switch(opt)
      {
         case 'l': 
            flags->ffileName = 1;
            flags->fileName = optarg;
            break;
         case 'x': 
            flags->fexecute = 1;
            break;
         case 's': 
            flags->fsize = 1;
            flags->size  = atoi(optarg); // should check the type of optarg
            break;
         case 'p':
            flags->fpad = 1;
            flags->pad  = atoi(optarg);
            break;
         /*case 'r': 
            flags->fret = 1;
            flags->ret  = optarg;
            break;*/
         case 'd': 
            flags->fdisplay = 1;
            if( 0 != optarg )
            {
               flags->display  = optarg;
            }
            else
            {
               flags->display = displayDefault;
            }
            break;
         case 'h': 
            help();
            break;
         case 'b':
            flags->fbadchar = 1;
            flags->badchar = optarg;
            break;
         case '?':
            abort_("[!] Syntax error\n");
            break;
      }
   }
   checkArgs(*flags);
   return EXIT_SUCCESS;
}



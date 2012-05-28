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

#include <string.h>
#include <sys/stat.h> // for fstat

int sctest(ShellCode const sc)
{
   int(*shellcode)() = (int (*)())sc.code;
   shellcode();
   return EXIT_SUCCESS;
}

int scload(const char *fileName, ShellCode *sc)
{
   // file descriptor
   FILE *fd;
   // file number
   int fileNo;
   // stat
   struct stat pstat;
   // size of the shellcode file
   off_t size;

   // pointer to output string
   ShellCodeByte *ptr;
   //
   int x, i;

   FOPEN(fd, fileName, "rb");

   fileNo = fileno(fd);
   if( 0 != fstat(fileNo, &pstat) )
   {
      info("Cannot fstat file", ERROR);
      return EXIT_FAILURE;
   }
   
   size = pstat.st_size;
   sc->size = size;
   sc->code = (ShellCodeByte*)malloc(size);

   ptr = sc->code;
   i = 0;
   while( ! feof(fd) && i < sc->size )
   {
      if( 1 != fread(&x, 1, 1, fd) )
      {
         break;
      }
      x = x & 0xff;
      *ptr = x;
      ++ptr;
      ++i;
   }
   fclose(fd);
   return EXIT_SUCCESS;
}

int screlease(ShellCode *sc)
{
   if( NULL != sc->code )
      free(sc->code);
   sc->size = 0;
   sc = NULL;
   return EXIT_SUCCESS;
}

int sccheckbadchar(const char const *badchars, const ShellCode sc)
{
   ShellCode badCharList;
   char temp[1024];
   int i, j;

   hex2sc(&badCharList, "", badchars);
   
   for( i = 0 ; i < badCharList.size ; ++ i )
   {
      for( j = 0 ; j < sc.size ; ++ j )
      {
         if( *(sc.code+j) == *(badCharList.code+i) )
         {
            sprintf(temp, "Badchar detected (\\x%.2x at position %d)!", *(sc.code+j)&0xff, j);
            info(temp, ERROR);
            return EXIT_FAILURE;
         }
      }
   }
   return EXIT_SUCCESS;

}


int scpad(ShellCode *sc, size_t newSize, size_t padding)
{
   size_t nopSledSize;
   ShellCodeByte *buf;
   ShellCodeByte *ptr;
   

   if( sc->size > newSize - padding )
   {
      info("ShellCode is too big for padding", WARNING);
      return EXIT_FAILURE;
   }

   nopSledSize = newSize - sc->size - padding;
   
   buf = (ShellCodeByte *)malloc(newSize);
   ptr = buf;
   incmemset(&ptr, '\x90', nopSledSize);
   incmemcpy(&ptr, sc->code, sc->size);
   incmemset(&ptr, '\x90', padding);

   free(sc->code);
   sc->size = newSize;
   sc->code = buf;
   return EXIT_SUCCESS;
}

int hex2sc(ShellCode *sc, const char *hexHeader, const char *scHex)
{
   size_t hexHeaderLen;
   size_t scHexLen;
   char buf[3];
   const char *ptr;
   char *scptr;;
   unsigned int x;

   hexHeaderLen = strlen(hexHeader);
   scHexLen = strlen(scHex);

   sc->size = scHexLen / (hexHeaderLen + 2);
   sc->code = (ShellCodeByte *)malloc( sc->size );
   scptr = sc->code;

   for( ptr = scHex ; *ptr != '\0' ; ptr += 2 )
   {
      ptr += hexHeaderLen;
      strncpy(buf, ptr, 2);
      *(buf + 2) = '\0';
      sscanf(buf, "%x", &x);
      *scptr = x&0xff;
      ++ scptr;
   }
   return EXIT_SUCCESS;
}

int sc2hex(const ShellCode sc, const char *hexHeader, char **scHex)
{
   int i, j;
   size_t hexHeaderLen;
   char *ptr;

   hexHeaderLen = strlen(hexHeader);
   // Allocate 2 byte per shellcode byte (inhexadecimal, it prints in 2 character) + the size of the header
   // e.g. sc[0] = '\x90' is 1 byte in bytecode but 4 chars when displayed
   *scHex = (char*)malloc(sc.size*(2+hexHeaderLen)+1);
   ptr = *scHex;
   for( j = 0 ; j < sc.size ; ++ j )
   {
      // copy all headers characters
      for( i = 0 ; i < hexHeaderLen ; ++ i )
      {
         *ptr = hexHeader[i];
         ++ ptr;
      }
      // copy the shellcode byte in 2-char format
      sprintf(ptr, "%.2x", (*(sc.code+j))&0xff);
      ptr+=2;
   }
   *ptr = '\0';
   return EXIT_SUCCESS;
}


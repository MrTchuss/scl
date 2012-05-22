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
#include <fcntl.h>   // for open and associated O_* flags
#include <sys/mman.h> // for mmap
#include <unistd.h> // for close

int sctest(ShellCode const sc)
{
   int(*shellcode)() = (int (*)())sc.code;
   shellcode();
   return EXIT_SUCCESS;
}

int scload(const char *fileName, ShellCode *sc)
{
   // file descriptor
   int fd;
   // stat
   struct stat pstat;
   // size of the shellcode file
   off_t size;

   OPEN(fd, fileName, O_RDONLY, 0);
   
   if( 0 != fstat(fd, &pstat) )
   {
      info("Cannot fstat file", ERROR);
      return EXIT_FAILURE;
   }
   
   size = pstat.st_size;
   sc->size = size;
   sc->code = (ShellCodeByte*)mmap(NULL, sc->size, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
   close(fd);
   if( MAP_FAILED == sc->code() )
   {
      info("Cannot load shellcode (mmap failed)", ERROR);
      return EXIT_FAILURE;
   }
   return EXIT_SUCCESS;
}

int screlease(ShellCode *sc)
{
   // TODO The addr must be a multiple of the page size.
   if( 0 != munmap(sc->code, sc->size) )
   {
      info("Error in destructing shellcode", ERROR);
      return EXIT_FAILURE;
   }
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


int scpad(ShellCode *sc, size_t newSize, size_t padding, char *fileName)
{
   // if specified, a file with pad data will be created
   if( fileName != NULL )
   {

   }
   else
   {
   }
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


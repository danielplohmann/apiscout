/*************************************************************************
 * Copyright (c) 2017
 * Daniel Plohmann <daniel.plohmann<at>mailbox<dot>org>
 * All rights reserved.
 *************************************************************************
 *
 *  This file is part of apiscout
 *
 *  apiscout is free software: you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see
 *  <http://www.gnu.org/licenses/>.
 *
 ***********************************************************************/

#include <windows.h>
#include <tchar.h>
#include <winbase.h>
#include <stdio.h>

// bitness check courtesy of http://stackoverflow.com/a/12338526
 // Check windows
#if _WIN32 || _WIN64
   #if _WIN64
     #define ENV64BIT
  #else
    #define ENV32BIT
  #endif
#endif

// Check GCC
#if __GNUC__
  #if __x86_64__ || __ppc64__
    #define ENV64BIT
  #else
    #define ENV32BIT
  #endif
#endif

int main() {
    DWORD written_b = 0;
    HANDLE hStdOut = 0;
    HINSTANCE hDllBase = 0;
    LPWSTR* szArglist;
    char buffer [50];
    int nArgs;

    hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);

    if( nArgs > 1 ) {
        GetFileAttributesW(szArglist[1]); // from winbase.h
        if(INVALID_FILE_ATTRIBUTES == GetFileAttributesW(szArglist[1]) && GetLastError()==ERROR_FILE_NOT_FOUND)
        {
            char cFileNotFound[] = "DLL not found?\n";
            WriteFile(hStdOut, cFileNotFound, strlen(cFileNotFound), &written_b, 0);
            return 0;
        } else {
            // suppress output of popups (Entry Point not found etc.)
            UINT oldErrorMode = SetErrorMode(SEM_FAILCRITICALERRORS);
            SetErrorMode(oldErrorMode | SEM_FAILCRITICALERRORS);
            hDllBase = LoadLibraryW(szArglist[1]);

        }
    } else {
        char output[] = "Usage: DllBaseChecker[32|64].exe <dll_to_load>";
        WriteFile(hStdOut, output, strlen(output), &written_b, 0);
        return 0;
    }
    #if defined(ENV64BIT)
        if (sizeof(void*) != 8)
        {
            wprintf(L"ENV64BIT: Error: pointer should be 8 bytes. Exiting.");
            return 0;
        } else {
            sprintf(buffer, "DLL loaded at: 0x%llx\n", hDllBase);
            WriteFile(hStdOut, buffer, strlen(buffer), &written_b, 0);
        }
    #elif defined (ENV32BIT)
        if (sizeof(void*) != 4)
        {
            wprintf(L"ENV32BIT: Error: pointer should be 4 bytes. Exiting.");
            return 0;
        } else {
            sprintf(buffer, "DLL loaded at: 0x%x\n", (unsigned int)hDllBase);
            WriteFile(hStdOut, buffer, strlen(buffer), &written_b, 0);
        }
    #else
        #error "Must define either ENV32BIT or ENV64BIT".
    #endif
    return 0;
}
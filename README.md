# FileNuke
FileNuke is a small program to help delete files which are being held open by other processes. \
This can mean open file handles or memory mapped files like dll. The program utilizes several "undocumented" ntdll.dll functions. \
Undocumented is in quotes as you can find documentation for those but there isn't any guarantee that the API will not break in \
future windows updates. In practice this means we will resolve those functions dynamically during runtime.

## How does it work
Memory mapped files such as dll files can easily be queried with standard WinAPI but unmapping those forcibly from other processes \
requires us to utilize NtUnmapViewOfFileEx which is an "undocumented" ntdll.dll function. \
Closing remote file handles is a bit trickier and it requires to use NtQuerySystemInformation to get information about the opened \
file handles of other process, NtDuplicateObject to create a copy of the handle for our program to parse the information, \
NtQueryObject to query information about the type of the handle and the name of the file if it is a file handle. \
Finally when we have identified a remote handle we wish to close we use NtDuplicateObject with DUPLICATE_CLOSE_SOURCE which will \
close the handle in remote process.

When all file mapping and file handles have been closed in remote processes then NtDeleteFile is used to delete the file.

## Remarks
The ntdll.dll functions used by the program are subject to change without notice in windows updates which means that if it happens \
this causes undefined behavior of this program. This program is for a simple utility and a PoC

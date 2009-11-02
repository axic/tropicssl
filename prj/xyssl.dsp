# Microsoft Developer Studio Project File - Name="xyssl" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=xyssl - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "xyssl.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "xyssl.mak" CFG="xyssl - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "xyssl - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "xyssl - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "xyssl - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /D "SELF_TEST" /YX /FD /c
# ADD CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /D "SELF_TEST" /YX /FD /c
# ADD BASE RSC /l 0x40c /d "NDEBUG"
# ADD RSC /l 0x40c /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "xyssl - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /D "SELF_TEST" /YX /FD /GZ /c
# ADD CPP /nologo /ML /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /D "SELF_TEST" /YX /FD /GZ /c
# ADD BASE RSC /l 0x40c /d "_DEBUG"
# ADD RSC /l 0x40c /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ENDIF 

# Begin Target

# Name "xyssl - Win32 Release"
# Name "xyssl - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\src\aes.c
# End Source File
# Begin Source File

SOURCE=..\src\arc4.c
# End Source File
# Begin Source File

SOURCE=..\src\base64.c
# End Source File
# Begin Source File

SOURCE=..\src\des.c
# End Source File
# Begin Source File

SOURCE=..\src\havege.c
# End Source File
# Begin Source File

SOURCE=..\src\md2.c
# End Source File
# Begin Source File

SOURCE=..\src\md4.c
# End Source File
# Begin Source File

SOURCE=..\src\md5.c
# End Source File
# Begin Source File

SOURCE=..\src\mpi.c
# End Source File
# Begin Source File

SOURCE=..\src\net.c
# End Source File
# Begin Source File

SOURCE=..\src\rsa.c
# End Source File
# Begin Source File

SOURCE=..\src\sha1.c
# End Source File
# Begin Source File

SOURCE=..\src\sha2.c
# End Source File
# Begin Source File

SOURCE=..\src\ssl_cli.c
# End Source File
# Begin Source File

SOURCE=..\src\ssl_v3.c
# End Source File
# Begin Source File

SOURCE=..\src\timing.c
# End Source File
# Begin Source File

SOURCE=..\src\x509_in.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\src\aes.h
# End Source File
# Begin Source File

SOURCE=..\src\arc4.h
# End Source File
# Begin Source File

SOURCE=..\src\base64.h
# End Source File
# Begin Source File

SOURCE=..\src\des.h
# End Source File
# Begin Source File

SOURCE=..\src\error.h
# End Source File
# Begin Source File

SOURCE=..\src\havege.h
# End Source File
# Begin Source File

SOURCE=..\src\md2.h
# End Source File
# Begin Source File

SOURCE=..\src\md4.h
# End Source File
# Begin Source File

SOURCE=..\src\md5.h
# End Source File
# Begin Source File

SOURCE=..\src\mpi.h
# End Source File
# Begin Source File

SOURCE=..\src\net.h
# End Source File
# Begin Source File

SOURCE=..\src\rsa.h
# End Source File
# Begin Source File

SOURCE=..\src\sha1.h
# End Source File
# Begin Source File

SOURCE=..\src\sha2.h
# End Source File
# Begin Source File

SOURCE=..\src\ssl_v3.h
# End Source File
# Begin Source File

SOURCE=..\src\timing.h
# End Source File
# Begin Source File

SOURCE=..\src\x509.h
# End Source File
# End Group
# End Target
# End Project

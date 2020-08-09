// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "HookFunc.h"

# define EXTERNC extern "C"
# define NAKED __declspec(naked)
# define EXPORT EXTERNC __declspec(dllexport)
# define ALCPP EXPORT NAKED
# define ALSTD EXTERNC EXPORT NAKED void __stdcall
# define ALCFAST EXTERNC EXPORT NAKED void __fastcall
# define ALCDECL EXTERNC NAKED void __cdecl



namespace DLLHijacker
{
    HMODULE m_hModule = NULL;
    DWORD m_dwReturn[17] = { 0 };

    inline BOOL WINAPI Load()
    {
        TCHAR tzPath[MAX_PATH];
        lstrcpy(tzPath, TEXT("libTDAjust"));
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

ALCDECL Hijack_TDAjustCreateInstance(void)
{
    __asm POP m_dwReturn[0 * TYPE long];
    GetAddress("TDAjustCreateInstance")();
    __asm JMP m_dwReturn[0 * TYPE long];
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBox(NULL, L"dll已成功注入目标进程", L"成功", MB_OK);
        ControlInit();          //初始化控制模块
        HookInit();             //初始化hook模块
        GetTrueFuncAddress();   //获取真实的函数地址
       SetHooks();             //设置hook
        break;
    case DLL_PROCESS_DETACH:
        UnHooks();              //卸载hook
        HookFree();             //释放资源，要先Unhook，否则JY会UAF
        break;
    }
    return TRUE;
}



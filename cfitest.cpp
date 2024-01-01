#include "stdafx.h"
#include "util.h"
#include "testver.h"

extern "C" __declspec(noinline) void __cdecl cfgcaller(void(__cdecl * target)()) {
    target();
}
__declspec(noinline) void __cdecl cfgtarget() {
}

void cfgtestvalidcall() {
    cfgcaller(cfgtarget);
}

int cfitest(MitigTestMode mode, DWORD64(&policy)[2]) {
    if (!TestWindowsVersion(10, 0, 15063))
        printf("unsupported Windows version, might not be able to set mitigation policy\n");
    if (mode == MT_CET && !TestWindowsVersion(10, 0, 19041))
        printf("unsupported Windows version, program might not work correctly\n");
    auto path = new wchar_t[MAX_PATH];
    if (!GetModuleFileNameW(NULL, path, MAX_PATH))
        throw std::system_error(GetLastError(), std::system_category(), "GetModuleFileNameW");
    PROCESS_INFORMATION pi{};
    STARTUPINFOEXW si{ sizeof(si) };
    SIZE_T attrListSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);
    if (!attrListSize)
        throw std::runtime_error("attrListSize=0");
    si.lpAttributeList = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(calloc(1, attrListSize));
    if (!si.lpAttributeList)
        throw std::bad_alloc();
    if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrListSize))
        throw std::system_error(GetLastError(), std::system_category(), "InitializeProcThreadAttributeList");
    if (!UpdateProcThreadAttribute(
        si.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
        policy,
        sizeof(policy),
        NULL,
        NULL))
        throw std::system_error(GetLastError(), std::system_category(), "UpdateProcThreadAttribute");
    if (!CreateProcessW(
        path,
        _wcsdup(mitig_cmdlines[mode]),
        NULL,
        NULL,
        TRUE,
        EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        reinterpret_cast<LPSTARTUPINFOW>(&si),
        &pi))
        throw std::system_error(GetLastError(), std::system_category(), "CreateProcessW");
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode;
    if (!GetExitCodeProcess(pi.hProcess, &exitCode))
        throw std::system_error(GetLastError(), std::system_category(), "GetExitCodeProcess");
    printf("target exited with code: %08lx\n", exitCode);
    switch (mode) {
    case MT_CFG:
    case MT_CET:
        // both cause a fastfail
        if (exitCode == STATUS_STACK_BUFFER_OVERRUN)
            printf("fault detected, mitigation is active\n");
        break;
    default:
        break;
    }
    return 0;
}

#include "stdafx.h"
#include <WerApi.h>
#include <shellapi.h>
#include "wertool.h"

#pragma comment(lib, "Wer.lib")

int dowerexclude() {
    HRESULT hr = WerAddExcludedApplication(L"mitigtest.exe", TRUE);
    if (FAILED(hr))
        throw std::system_error(hr, std::system_category(), "WerAddExcludedApplication");
    printf("WerAddExcludedApplication OK\n");
    HKEY dumpKey;
    LSTATUS status = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\mitigtest.exe",
        0,
        NULL,
        0,
        KEY_ALL_ACCESS,
        NULL,
        &dumpKey,
        NULL);
    if (status)
        throw std::system_error(status, std::system_category(), "RegCreateKeyExW: cannot disable dumps");
    DWORD dumpCount = 0;
    status = RegSetValueExW(dumpKey, L"DumpCount", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dumpCount), sizeof(dumpCount));
    if (status)
        throw std::system_error(status, std::system_category(), "RegSetValueExW: cannot disable dumps");
    printf("disable dumps OK\n");
    system("pause");
    return 0;
}

int dowerunexclude() {
    HRESULT hr = WerRemoveExcludedApplication(L"mitigtest.exe", TRUE);
    if (FAILED(hr))
        throw std::system_error(hr, std::system_category(), "WerRemoveExcludedApplication");
    printf("WerRemoveExcludedApplication OK\n");
    LSTATUS status = RegDeleteKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\mitigtest.exe",
        0,
        0);
    if (status)
        throw std::system_error(status, std::system_category(), "RegDeleteKeyExW: cannot undisable dumps");
    printf("undisable dumps OK\n");
    system("pause");
    return 0;
}

int werruncmd(MitigTestMode mode) {
    auto path = new wchar_t[MAX_PATH];
    if (!GetModuleFileNameW(NULL, path, MAX_PATH))
        throw std::system_error(GetLastError(), std::system_category(), "GetModuleFileNameW");
    SHELLEXECUTEINFOW info{ sizeof(info) };
    info.lpVerb = L"runas";
    info.lpFile = path;
    info.lpParameters = mitig_cmdlines[mode];
    info.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&info))
        throw std::system_error(GetLastError(), std::system_category(), "ShellExecuteExW");
    if (info.hProcess)
        WaitForSingleObject(info.hProcess, INFINITE);
    return 0;
}

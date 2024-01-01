#include "testver.h"
#include <VersionHelpers.h>

typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
typedef NTSTATUS(NTAPI* RtlGetVersion_t)(_Out_ POSVERSIONINFOEXW VersionInformation);

bool TestWindowsVersion(DWORD major, DWORD minor, DWORD build) {
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        throw std::system_error(GetLastError(), std::system_category(), "GetModuleHandleW ntdll");
    auto rtlGetVersion = reinterpret_cast<RtlGetVersion_t>(GetProcAddress(ntdll, "RtlGetVersion"));
    if (!rtlGetVersion)
        throw std::system_error(GetLastError(), std::system_category(), "GetProcAddress RtlGetVersion");
    OSVERSIONINFOEXW vi;
    NTSTATUS status = rtlGetVersion(&vi);
    if (status < 0)
        throw std::runtime_error("failed to get Windows version");
    if (vi.dwMajorVersion != major)
        return (vi.dwMajorVersion > major);
    if (vi.dwMinorVersion != minor)
        return (vi.dwMinorVersion > minor);
    return (vi.dwBuildNumber >= build);
}

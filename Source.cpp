#include "stdafx.h"
#include "util.h"
#include "cfitest.h"
#include "wertool.h"

const wchar_t* mitig_cmdlines[] = {
    L"mitigtest.exe cfgtest",
    L"mitigtest.exe cettest",
    L"dowerexclude",
    L"dowerunexclude",
};

int main(int argc, char** argv) {
    MitigTestMode mode = MT_MAX;
    DWORD64 policy[2] = { 0, 0 };
    if (argc > 1) {
        if (!strcmp("cfgon", argv[1])) {
            mode = MT_CFG;
            policy[0] = PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_ON;
        }
        else if (!strcmp("cfgoff", argv[1])) {
            mode = MT_CFG;
            policy[0] = PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_OFF;
        }
        else if (!strcmp("ceton", argv[1])) {
            mode = MT_CET;
            policy[1] = PROCESS_CREATION_MITIGATION_POLICY2_CET_USER_SHADOW_STACKS_ALWAYS_ON;
        }
        else if (!strcmp("cetoff", argv[1])) {
            mode = MT_CET;
            policy[1] = PROCESS_CREATION_MITIGATION_POLICY2_CET_USER_SHADOW_STACKS_ALWAYS_OFF;
        }
        else if (!strcmp("cetstrict", argv[1])) {
            mode = MT_CET;
            policy[1] = PROCESS_CREATION_MITIGATION_POLICY2_CET_USER_SHADOW_STACKS_STRICT_MODE;
        }
        else if (!strcmp("werexclude", argv[1])) {
            mode = MT_WEREXCLUDE;
        }
        else if (!strcmp("werunexclude", argv[1])) {
            mode = MT_WERUNEXCLUDE;
        }
        // things from this point should return without creating a new process
        else if (!strcmp("cfgtest", argv[1])) {
            printf("testing valid icall\n");
            cfgtestvalidcall();
            printf("testing cfg violation\n");
            cfgtest();
            printf("cfg violation not detected\n");
            return 0;
        }
        else if (!strcmp("cettest", argv[1])) {
            printf("testing cet violation\n");
            cettest();
            printf("cet violation not detected\n");
            return 0;
        }
        else if (!strcmp("dowerexclude", argv[1])) {
            try {
                return dowerexclude();
            }
            catch (const std::exception& e) {
                printf("exception: %s\n", e.what());
                return 1;
            }
        }
        else if (!strcmp("dowerunexclude", argv[1])) {
            try {
                return dowerunexclude();
            }
            catch (const std::exception& e) {
                printf("exception: %s\n", e.what());
                return 1;
            }
        }
    }
    try {
        if (!CreateMutexW(NULL, TRUE, L"{63109E89-3018-4D51-8899-A2592538D1BA}"))
            throw std::system_error(GetLastError(), std::system_category(), "CreateMutexW");
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            printf("another instance is already running\n");
            return 0;
        }
        switch (mode) {
        case MT_CFG:
        case MT_CET:
            return cfitest(mode, policy);
        case MT_WEREXCLUDE:
        case MT_WERUNEXCLUDE:
            return werruncmd(mode);
        default:
            printf("usage: %s [cfgon|cfgoff|ceton|cetoff|cetstrict]\n", argv[0]);
            return 0;
        }
    }
    catch (const std::exception& e) {
        printf("exception: %s\n", e.what());
        return 1;
    }
}

#pragma once

enum MitigTestMode : unsigned int {
    MT_CFG,
    MT_CET,
    MT_WEREXCLUDE,
    MT_WERUNEXCLUDE,
    MT_MAX,
};

extern const wchar_t* mitig_cmdlines[];

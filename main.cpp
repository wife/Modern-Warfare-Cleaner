int __cdecl main(int argc, const char **argv, const char **envp)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  v3 = GetTickCount();
  srand(v3);
  LoadLibraryW(L"ntdll.dll");
  v4 = GetModuleHandleW(L"ntdll.dll");
  v5 = 0;
  NtQueryKey = (__int64 (__fastcall *)(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD))GetProcAddress(v4, "NtQueryKey");
  Luid = 0i64;
  if ( !LookupPrivilegeValueW(0i64, L"SeTakeOwnershipPrivilege", &Luid) )
  {
    v6 = GetLastError();
    sub_140001010("Failed to lookup privilege %ws: %d\n", L"SeTakeOwnershipPrivilege", v6);
LABEL_10:
    sub_140001010("failed to adjust privilege\n");
    return 1;
  }
  NewState.Privileges[0].Luid = Luid;
  NewState.PrivilegeCount = 1;
  NewState.Privileges[0].Attributes = 2;
  TokenHandle = 0i64;
  v7 = GetCurrentProcess();
  if ( !OpenProcessToken(v7, 0x20u, &TokenHandle) )
  {
    v8 = GetLastError();
    sub_140001010("Failed to open current process token: %d\n", v8);
    goto LABEL_10;
  }
  if ( !AdjustTokenPrivileges(TokenHandle, 0, &NewState, 0x10u, 0i64, 0i64) )
  {
    v9 = GetLastError();
    sub_140001010("Failed to adjust current process token privileges: %d\n", v9);
LABEL_9:
    CloseHandle(TokenHandle);
    goto LABEL_10;
  }
  if ( GetLastError() == 1300 )
  {
    sub_140001010("Token failed to acquire privilege\n");
    goto LABEL_9;
  }
  CloseHandle(TokenHandle);
  TokenHandle = 0i64;
  if ( RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY", 0, 0xF003Fu, (PHKEY)&TokenHandle) )
  {
    Luid.LowPart = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &Luid);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY");
  }
  else
  {
    v11 = (HKEY)TokenHandle;
    sub_140007460(&Name, 0i64, 520i64);
    v12 = 0;
    cchName = 520;
    if ( !RegEnumKeyExW(v11, 0, (LPWSTR)&Name, &cchName, 0i64, 0i64, 0i64, 0i64) )
    {
      do
      {
        phkResult = 0i64;
        if ( RegOpenKeyExW(v11, (LPCWSTR)&Name, 0, 0xF003Fu, &phkResult) )
        {
          Luid.LowPart = 520;
          sub_140007460(&qword_140028C50, 0i64, 520i64);
          NtQueryKey(v11, 3i64, &qword_140028C50, 520i64, &Luid);
          sub_140001010("Failed to open key: %ws\\%ws\n\n", (char *)&qword_140028C50 + 6, &Name);
        }
        else
        {
          v13 = phkResult;
          sub_140007460(SubKey, 0i64, 520i64);
          v14 = 0;
          v173 = 520;
          if ( !RegEnumKeyExW(v13, 0, SubKey, &v173, 0i64, 0i64, 0i64, 0i64) )
          {
            do
            {
              hKey = 0i64;
              if ( RegOpenKeyExW(v13, SubKey, 0, 0xF003Fu, &hKey) )
              {
                Luid.LowPart = 520;
                sub_140007460(&qword_140028C50, 0i64, 520i64);
                NtQueryKey(v13, 3i64, &qword_140028C50, 520i64, &Luid);
                sub_140001010("Failed to open key: %ws\\%ws\n\n", (char *)&qword_140028C50 + 6, SubKey);
              }
              else
              {
                v15 = hKey;
                sub_140007460(pszSubKey, 0i64, 520i64);
                v16 = 0;
                cbData = 520;
                if ( !RegEnumKeyExW(v15, 0, pszSubKey, &cbData, 0i64, 0i64, 0i64, 0i64) )
                {
                  while ( stricmp((const char *)pszSubKey, L"device parameters") )
                  {
                    ++v16;
                    cbData = 520;
                    if ( RegEnumKeyExW(v15, v16, pszSubKey, &cbData, 0i64, 0i64, 0i64, 0i64) )
                      goto LABEL_24;
                  }
                  sub_140005730(v15, pszSubKey, L"EDID");
                }
LABEL_24:
                RegCloseKey(v15);
              }
              ++v14;
              v173 = 520;
            }
            while ( !RegEnumKeyExW(v13, v14, SubKey, &v173, 0i64, 0i64, 0i64, 0i64) );
          }
          RegCloseKey(v13);
        }
        ++v12;
        cchName = 520;
      }
      while ( !RegEnumKeyExW(v11, v12, (LPWSTR)&Name, &cchName, 0i64, 0i64, 0i64, 0i64) );
    }
    RegCloseKey(v11);
  }
  sub_140005C90(-2147483646i64, L"SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data", L"SMBiosData");
  hKey = 0i64;
  if ( RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\HardwareConfig", 0, 0xF003Fu, &hKey) )
  {
    Luid.LowPart = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &Luid);
    sub_140001010("Failed to open key: %ws\\%ws\n\n", (char *)&qword_140028C50 + 6, L"SYSTEM\\HardwareConfig");
  }
  else
  {
    sub_140007460(v179, 0i64, 520i64);
    v17 = hKey;
    sub_1400050D0(hKey, L"LastConfig", (BYTE *)v179);
    sub_140007460(&Name, 0i64, 520i64);
    v18 = 0;
    cchName = 520;
    if ( !RegEnumKeyExW(v17, 0, (LPWSTR)&Name, &cchName, 0i64, 0i64, 0i64, 0i64) )
    {
      while ( !stricmp((const char *)&Name, L"current") )
      {
        ++v18;
        cchName = 520;
        if ( RegEnumKeyExW(v17, v18, (LPWSTR)&Name, &cchName, 0i64, 0i64, 0i64, 0i64) )
          goto LABEL_36;
      }
      sub_140005970(v17, (LPCWSTR)&Name, v179);
    }
LABEL_36:
    RegCloseKey(v17);
  }
  hKey = 0i64;
  if ( RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\NVIDIA Corporation\\Global", 0, 0xF003Fu, &hKey) )
  {
    Luid.LowPart = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &Luid);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SOFTWARE\\NVIDIA Corporation\\Global");
  }
  else
  {
    v19 = hKey;
    sub_140007460(v179, 0i64, 520i64);
    sub_1400050D0(v19, L"ClientUUID", (BYTE *)v179);
    RegCloseKey(v19);
  }
  hKey = 0i64;
  if ( RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\NVIDIA Corporation\\Global", 0, 0xF003Fu, &hKey) )
  {
    Luid.LowPart = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &Luid);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SOFTWARE\\NVIDIA Corporation\\Global");
  }
  else
  {
    v20 = hKey;
    sub_140007460(v179, 0i64, 520i64);
    sub_1400050D0(v20, L"PersistenceIdentifier", (BYTE *)v179);
    RegCloseKey(v20);
  }
  hKey = 0i64;
  if ( RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\NVIDIA Corporation\\Global\\CoProcManager", 0, 0xF003Fu, &hKey) )
  {
    Luid.LowPart = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &Luid);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SOFTWARE\\NVIDIA Corporation\\Global\\CoProcManager");
  }
  else
  {
    v21 = hKey;
    sub_140007460(v179, 0i64, 520i64);
    sub_1400050D0(v21, L"ChipsetMatchID", (BYTE *)v179);
    RegCloseKey(v21);
  }
  sub_140005B90(-2147483646i64, L"SYSTEM\\MountedDevices");
  sub_140005B90(-2147483646i64, L"SOFTWARE\\Microsoft\\Dfrg\\Statistics");
  sub_140005B90(-2147483647i64, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume");
  sub_140005B90(-2147483647i64, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume");
  sub_140005B90(-2147483647i64, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2");
  sub_140005C90(-2147483647i64, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket", L"LastEnum");
  hKey = 0i64;
  if ( RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI", 0, 0xF003Fu, &hKey) )
  {
    Luid.LowPart = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &Luid);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI");
  }
  else
  {
    v22 = hKey;
    cbData = 0;
    if ( RegQueryValueExW(hKey, L"WindowsAIKHash", 0i64, 0i64, 0i64, &cbData) )
    {
      Luid.LowPart = 520;
      sub_140007460(&qword_140028C50, 0i64, 520i64);
      NtQueryKey(v22, 3i64, &qword_140028C50, 520i64, &Luid);
      sub_140001010("Failed to query size of: %ws\\%ws\n\n", (char *)&qword_140028C50 + 6, L"WindowsAIKHash");
    }
    else
    {
      v23 = (BYTE *)j__malloc_base(cbData);
      if ( v23 )
      {
        v24 = cbData;
        for ( i = 0; i < cbData; v24 = cbData )
        {
          v26 = rand();
          v27 = i++;
          v23[v27] = v26;
        }
        RegSetValueExW(v22, L"WindowsAIKHash", 0, 3u, v23, v24);
        free(v23);
        Luid.LowPart = 520;
        sub_140007460(&qword_140028C50, 0i64, 520i64);
        NtQueryKey(v22, 3i64, &qword_140028C50, 520i64, &Luid);
        LODWORD(ReturnLengtha) = cbData;
        LODWORD(PreviousState) = 196;
        sub_140001010(
          "%ws\\%ws\n%c%c binary of length %d\n\n",
          (char *)&qword_140028C50 + 6,
          L"WindowsAIKHash",
          192i64,
          PreviousState,
          ReturnLengtha);
      }
      else
      {
        sub_140001010("Failed to allocate buffer for SpoofBinary\n\n");
      }
    }
    RegCloseKey(v22);
  }
  hKey = 0i64;
  if ( RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Direct3D", 0, 0xF003Fu, &hKey) )
  {
    Luid.LowPart = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483647i64, 3i64, &qword_140028C50, 520i64, &Luid);
    sub_140001010("Failed to open key: %ws\\%ws\n\n", (char *)&qword_140028C50 + 6, L"Software\\Microsoft\\Direct3D");
  }
  else
  {
    v28 = hKey;
    cbData = 0;
    if ( RegQueryValueExW(hKey, L"WHQLClass", 0i64, 0i64, 0i64, &cbData) )
    {
      Luid.LowPart = 520;
      sub_140007460(&qword_140028C50, 0i64, 520i64);
      NtQueryKey(v28, 3i64, &qword_140028C50, 520i64, &Luid);
      sub_140001010("Failed to query size of: %ws\\%ws\n\n", (char *)&qword_140028C50 + 6, L"WHQLClass");
    }
    else
    {
      v29 = (BYTE *)j__malloc_base(cbData);
      if ( v29 )
      {
        v30 = cbData;
        for ( j = 0; j < cbData; v30 = cbData )
        {
          v32 = rand();
          v33 = j++;
          v29[v33] = v32;
        }
        RegSetValueExW(v28, L"WHQLClass", 0, 3u, v29, v30);
        free(v29);
        Luid.LowPart = 520;
        sub_140007460(&qword_140028C50, 0i64, 520i64);
        NtQueryKey(v28, 3i64, &qword_140028C50, 520i64, &Luid);
        LODWORD(ReturnLengthb) = cbData;
        LODWORD(PreviousStatea) = 196;
        sub_140001010(
          "%ws\\%ws\n%c%c binary of length %d\n\n",
          (char *)&qword_140028C50 + 6,
          L"WHQLClass",
          192i64,
          PreviousStatea,
          ReturnLengthb);
      }
      else
      {
        sub_140001010("Failed to allocate buffer for SpoofBinary\n\n");
      }
    }
    RegCloseKey(v28);
  }
  hKey = 0i64;
  if ( RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\Installer\\Dependencies", 0, 0xF003Fu, &hKey) )
  {
    Luid.LowPart = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483647i64, 3i64, &qword_140028C50, 520i64, &Luid);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"Software\\Classes\\Installer\\Dependencies");
  }
  else
  {
    v34 = hKey;
    cbData = 0;
    if ( RegQueryValueExW(hKey, L"MSICache", 0i64, 0i64, 0i64, &cbData) )
    {
      Luid.LowPart = 520;
      sub_140007460(&qword_140028C50, 0i64, 520i64);
      NtQueryKey(v34, 3i64, &qword_140028C50, 520i64, &Luid);
      sub_140001010("Failed to query size of: %ws\\%ws\n\n", (char *)&qword_140028C50 + 6, L"MSICache");
    }
    else
    {
      v35 = (BYTE *)j__malloc_base(cbData);
      if ( v35 )
      {
        v36 = cbData;
        for ( k = 0; k < cbData; v36 = cbData )
        {
          v38 = rand();
          v39 = k++;
          v35[v39] = v38;
        }
        RegSetValueExW(v34, L"MSICache", 0, 3u, v35, v36);
        free(v35);
        Luid.LowPart = 520;
        sub_140007460(&qword_140028C50, 0i64, 520i64);
        NtQueryKey(v34, 3i64, &qword_140028C50, 520i64, &Luid);
        LODWORD(ReturnLengthc) = cbData;
        LODWORD(PreviousStateb) = 196;
        sub_140001010(
          "%ws\\%ws\n%c%c binary of length %d\n\n",
          (char *)&qword_140028C50 + 6,
          L"MSICache",
          192i64,
          PreviousStateb,
          ReturnLengthc);
      }
      else
      {
        sub_140001010("Failed to allocate buffer for SpoofBinary\n\n");
      }
    }
    RegCloseKey(v34);
  }
  hKey = 0i64;
  if ( RegOpenKeyExW(
         HKEY_LOCAL_MACHINE,
         L"HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0\\DiskController\\0\\DiskPeripheral",
         0,
         0xF003Fu,
         &hKey) )
  {
    Luid.LowPart = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &Luid);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0\\DiskController\\0\\DiskPeripheral");
  }
  else
  {
    v40 = hKey;
    sub_140007460(&Name, 0i64, 520i64);
    v41 = 0;
    cchName = 520;
    if ( !RegEnumKeyExW(v40, 0, (LPWSTR)&Name, &cchName, 0i64, 0i64, 0i64, 0i64) )
    {
      do
      {
        TokenHandle = 0i64;
        if ( RegOpenKeyExW(v40, (LPCWSTR)&Name, 0, 0xF003Fu, (PHKEY)&TokenHandle) )
        {
          Luid.LowPart = 520;
          sub_140007460(&qword_140028C50, 0i64, 520i64);
          NtQueryKey(v40, 3i64, &qword_140028C50, 520i64, &Luid);
          sub_140001010("Failed to open key: %ws\\%ws\n\n", (char *)&qword_140028C50 + 6, &Name);
        }
        else
        {
          v42 = (HKEY)TokenHandle;
          sub_140007460(v179, 0i64, 520i64);
          sub_1400050D0(v42, L"Identifier", (BYTE *)v179);
          RegCloseKey(v42);
        }
        ++v41;
        cchName = 520;
      }
      while ( !RegEnumKeyExW(v40, v41, (LPWSTR)&Name, &cchName, 0i64, 0i64, 0i64, 0i64) );
    }
    RegCloseKey(v40);
  }
  hKey = 0i64;
  if ( RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\Scsi", 0, 0xF003Fu, &hKey) )
  {
    Luid.LowPart = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &Luid);
    sub_140001010("Failed to open key: %ws\\%ws\n\n", (char *)&qword_140028C50 + 6, L"HARDWARE\\DEVICEMAP\\Scsi");
  }
  else
  {
    v43 = hKey;
    *(_QWORD *)&NewState.PrivilegeCount = hKey;
    sub_140007460(v179, 0i64, 520i64);
    v44 = 0;
    Luid.LowPart = 0;
    for ( LODWORD(phkResult) = 520;
          !RegEnumKeyExW(v43, v44, v179, (LPDWORD)&phkResult, 0i64, 0i64, 0i64, 0i64);
          LODWORD(phkResult) = 520 )
    {
      v167 = 0i64;
      if ( RegOpenKeyExW(v43, v179, 0, 0xF003Fu, &v167) )
      {
        Luid.LowPart = 520;
        sub_140007460(&qword_140028C50, 0i64, 520i64);
        NtQueryKey(v43, 3i64, &qword_140028C50, 520i64, &Luid);
        sub_140001010("Failed to open key: %ws\\%ws\n\n", (char *)&qword_140028C50 + 6, v179);
      }
      else
      {
        v45 = v167;
        sub_140007460(SubKey, 0i64, 520i64);
        cbData = 520;
        if ( !RegEnumKeyExW(v45, 0, SubKey, &cbData, 0i64, 0i64, 0i64, 0i64) )
        {
          do
          {
            v168 = 0i64;
            if ( RegOpenKeyExW(v45, SubKey, 0, 0xF003Fu, &v168) )
            {
              cchName = 520;
              sub_140007460(&qword_140028C50, 0i64, 520i64);
              NtQueryKey(v45, 3i64, &qword_140028C50, 520i64, &cchName);
              sub_140001010("Failed to open key: %ws\\%ws\n\n", (char *)&qword_140028C50 + 6, SubKey);
            }
            else
            {
              v46 = v168;
              sub_140007460(pszSubKey, 0i64, 520i64);
              v47 = 0;
              v173 = 520;
              if ( !RegEnumKeyExW(v46, 0, pszSubKey, &v173, 0i64, 0i64, 0i64, 0i64) )
              {
                do
                {
                  if ( sub_140006F20(pszSubKey, L"arget") )
                  {
                    v169 = 0i64;
                    if ( RegOpenKeyExW(v46, pszSubKey, 0, 0xF003Fu, &v169) )
                    {
                      cchName = 520;
                      sub_140007460(&qword_140028C50, 0i64, 520i64);
                      NtQueryKey(v46, 3i64, &qword_140028C50, 520i64, &cchName);
                      sub_140001010("Failed to open key: %ws\\%ws\n\n", (char *)&qword_140028C50 + 6, pszSubKey);
                    }
                    else
                    {
                      v48 = v169;
                      sub_140007460(&Name, 0i64, 520i64);
                      v49 = 0;
                      cchName = 520;
                      if ( !RegEnumKeyExW(v48, 0, (LPWSTR)&Name, &cchName, 0i64, 0i64, 0i64, 0i64) )
                      {
                        do
                        {
                          hkey = 0i64;
                          if ( RegOpenKeyExW(v48, (LPCWSTR)&Name, 0, 0xF003Fu, &hkey) )
                          {
                            LODWORD(TokenHandle) = 520;
                            sub_140007460(&qword_140028C50, 0i64, 520i64);
                            NtQueryKey(v48, 3i64, &qword_140028C50, 520i64, &TokenHandle);
                            sub_140001010("Failed to open key: %ws\\%ws\n\n", (char *)&qword_140028C50 + 6, &Name);
                          }
                          else
                          {
                            v50 = hkey;
                            sub_140007460(&FindFileData, 0i64, 520i64);
                            sub_1400050D0(v50, L"Identifier", (BYTE *)&FindFileData);
                            RegCloseKey(v50);
                          }
                          ++v49;
                          cchName = 520;
                        }
                        while ( !RegEnumKeyExW(v48, v49, (LPWSTR)&Name, &cchName, 0i64, 0i64, 0i64, 0i64) );
                      }
                      RegCloseKey(v48);
                    }
                  }
                  ++v47;
                  v173 = 520;
                }
                while ( !RegEnumKeyExW(v46, v47, pszSubKey, &v173, 0i64, 0i64, 0i64, 0i64) );
              }
              RegCloseKey(v46);
            }
            ++v5;
            cbData = 520;
          }
          while ( !RegEnumKeyExW(v45, v5, SubKey, &cbData, 0i64, 0i64, 0i64, 0i64) );
          v43 = *(HKEY *)&NewState.PrivilegeCount;
          v44 = Luid.LowPart;
        }
        RegCloseKey(v45);
        v5 = 0;
      }
      Luid.LowPart = ++v44;
    }
    RegCloseKey(v43);
  }
  hkey = 0i64;
  if ( RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\TPM\\ODUID", 0, 0xF003Fu, &hkey) )
  {
    LODWORD(TokenHandle) = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SYSTEM\\CurrentControlSet\\Services\\TPM\\ODUID");
  }
  else
  {
    v51 = hkey;
    cbData = 0;
    if ( RegQueryValueExW(hkey, L"RandomSeed", 0i64, 0i64, 0i64, &cbData) )
    {
      LODWORD(TokenHandle) = 520;
      sub_140007460(&qword_140028C50, 0i64, 520i64);
      NtQueryKey(v51, 3i64, &qword_140028C50, 520i64, &TokenHandle);
      sub_140001010("Failed to query size of: %ws\\%ws\n\n", (char *)&qword_140028C50 + 6, L"RandomSeed");
    }
    else
    {
      v52 = (BYTE *)j__malloc_base(cbData);
      if ( v52 )
      {
        v53 = cbData;
        for ( l = 0; l < cbData; v53 = cbData )
        {
          v55 = rand();
          v56 = l++;
          v52[v56] = v55;
        }
        RegSetValueExW(v51, L"RandomSeed", 0, 3u, v52, v53);
        free(v52);
        LODWORD(TokenHandle) = 520;
        sub_140007460(&qword_140028C50, 0i64, 520i64);
        NtQueryKey(v51, 3i64, &qword_140028C50, 520i64, &TokenHandle);
        LODWORD(ReturnLengthd) = cbData;
        LODWORD(PreviousStatec) = 196;
        sub_140001010(
          "%ws\\%ws\n%c%c binary of length %d\n\n",
          (char *)&qword_140028C50 + 6,
          L"RandomSeed",
          192i64,
          PreviousStatec,
          ReturnLengthd);
      }
      else
      {
        sub_140001010("Failed to allocate buffer for SpoofBinary\n\n");
      }
    }
    RegCloseKey(v51);
  }
  hkey = 0i64;
  if ( RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0, 0xF003Fu, &hkey) )
  {
    LODWORD(TokenHandle) = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SOFTWARE\\Microsoft\\Cryptography");
  }
  else
  {
    v57 = hkey;
    sub_140007460(&FindFileData, 0i64, 520i64);
    sub_1400050D0(v57, L"MachineGuid", (BYTE *)&FindFileData);
    RegCloseKey(v57);
  }
  hkey = 0i64;
  if ( RegOpenKeyExW(
         HKEY_LOCAL_MACHINE,
         L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001",
         0,
         0xF003Fu,
         &hkey) )
  {
    LODWORD(TokenHandle) = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001");
  }
  else
  {
    v58 = hkey;
    sub_140007460(&FindFileData, 0i64, 520i64);
    sub_1400050D0(v58, L"HwProfileGuid", (BYTE *)&FindFileData);
    RegCloseKey(v58);
  }
  hkey = 0i64;
  if ( RegOpenKeyExW(
         HKEY_LOCAL_MACHINE,
         L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
         0,
         0xF003Fu,
         &hkey) )
  {
    LODWORD(TokenHandle) = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate");
  }
  else
  {
    v59 = hkey;
    sub_140007460(&FindFileData, 0i64, 520i64);
    sub_1400050D0(v59, L"AccountDomainSid", (BYTE *)&FindFileData);
    RegCloseKey(v59);
  }
  hkey = 0i64;
  if ( RegOpenKeyExW(
         HKEY_LOCAL_MACHINE,
         L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
         0,
         0xF003Fu,
         &hkey) )
  {
    LODWORD(TokenHandle) = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate");
  }
  else
  {
    v60 = hkey;
    sub_140007460(&FindFileData, 0i64, 520i64);
    sub_1400050D0(v60, L"PingID", (BYTE *)&FindFileData);
    RegCloseKey(v60);
  }
  hkey = 0i64;
  if ( RegOpenKeyExW(
         HKEY_LOCAL_MACHINE,
         L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
         0,
         0xF003Fu,
         &hkey) )
  {
    LODWORD(TokenHandle) = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate");
  }
  else
  {
    v61 = hkey;
    sub_140007460(&FindFileData, 0i64, 520i64);
    sub_1400050D0(v61, L"SusClientId", (BYTE *)&FindFileData);
    RegCloseKey(v61);
  }
  hkey = 0i64;
  if ( RegOpenKeyExW(
         HKEY_LOCAL_MACHINE,
         L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
         0,
         0xF003Fu,
         &hkey) )
  {
    LODWORD(TokenHandle) = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate");
  }
  else
  {
    v62 = hkey;
    cbData = 0;
    if ( RegQueryValueExW(hkey, L"SusClientIdValidation", 0i64, 0i64, 0i64, &cbData) )
    {
      LODWORD(TokenHandle) = 520;
      sub_140007460(&qword_140028C50, 0i64, 520i64);
      NtQueryKey(v62, 3i64, &qword_140028C50, 520i64, &TokenHandle);
      sub_140001010("Failed to query size of: %ws\\%ws\n\n", (char *)&qword_140028C50 + 6, L"SusClientIdValidation");
    }
    else
    {
      v63 = (BYTE *)j__malloc_base(cbData);
      if ( v63 )
      {
        v64 = cbData;
        for ( m = 0; m < cbData; v64 = cbData )
        {
          v66 = rand();
          v67 = m++;
          v63[v67] = v66;
        }
        RegSetValueExW(v62, L"SusClientIdValidation", 0, 3u, v63, v64);
        free(v63);
        LODWORD(TokenHandle) = 520;
        sub_140007460(&qword_140028C50, 0i64, 520i64);
        NtQueryKey(v62, 3i64, &qword_140028C50, 520i64, &TokenHandle);
        LODWORD(ReturnLengthe) = cbData;
        LODWORD(PreviousStated) = 196;
        sub_140001010(
          "%ws\\%ws\n%c%c binary of length %d\n\n",
          (char *)&qword_140028C50 + 6,
          L"SusClientIdValidation",
          192i64,
          PreviousStated,
          ReturnLengthe);
      }
      else
      {
        sub_140001010("Failed to allocate buffer for SpoofBinary\n\n");
      }
    }
    RegCloseKey(v62);
  }
  hkey = 0i64;
  if ( RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters", 0, 0xF003Fu, &hkey) )
  {
    LODWORD(TokenHandle) = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters");
  }
  else
  {
    v68 = hkey;
    cbData = 0;
    if ( RegQueryValueExW(hkey, L"Dhcpv6DUID", 0i64, 0i64, 0i64, &cbData) )
    {
      LODWORD(TokenHandle) = 520;
      sub_140007460(&qword_140028C50, 0i64, 520i64);
      NtQueryKey(v68, 3i64, &qword_140028C50, 520i64, &TokenHandle);
      sub_140001010("Failed to query size of: %ws\\%ws\n\n", (char *)&qword_140028C50 + 6, L"Dhcpv6DUID");
    }
    else
    {
      v69 = (BYTE *)j__malloc_base(cbData);
      if ( v69 )
      {
        v70 = cbData;
        for ( n = 0; n < cbData; v70 = cbData )
        {
          v72 = rand();
          v73 = n++;
          v69[v73] = v72;
        }
        RegSetValueExW(v68, L"Dhcpv6DUID", 0, 3u, v69, v70);
        free(v69);
        LODWORD(TokenHandle) = 520;
        sub_140007460(&qword_140028C50, 0i64, 520i64);
        NtQueryKey(v68, 3i64, &qword_140028C50, 520i64, &TokenHandle);
        LODWORD(ReturnLengthf) = cbData;
        LODWORD(PreviousStatee) = 196;
        sub_140001010(
          "%ws\\%ws\n%c%c binary of length %d\n\n",
          (char *)&qword_140028C50 + 6,
          L"Dhcpv6DUID",
          192i64,
          PreviousStatee,
          ReturnLengthf);
      }
      else
      {
        sub_140001010("Failed to allocate buffer for SpoofBinary\n\n");
      }
    }
    RegCloseKey(v68);
  }
  hkey = 0i64;
  if ( RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation", 0, 0xF003Fu, &hkey) )
  {
    LODWORD(TokenHandle) = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation");
  }
  else
  {
    v74 = hkey;
    sub_140007460(&FindFileData, 0i64, 520i64);
    sub_1400050D0(v74, L"ComputerHardwareId", (BYTE *)&FindFileData);
    RegCloseKey(v74);
  }
  sub_1400052C0();
  hkey = 0i64;
  if ( RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Internet Explorer\\Migration", 0, 0xF003Fu, &hkey) )
  {
    LODWORD(TokenHandle) = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SOFTWARE\\Microsoft\\Internet Explorer\\Migration");
  }
  else
  {
    v75 = hkey;
    cbData = 0;
    if ( RegQueryValueExW(hkey, L"IE Installed Date", 0i64, 0i64, 0i64, &cbData) )
    {
      LODWORD(TokenHandle) = 520;
      sub_140007460(&qword_140028C50, 0i64, 520i64);
      NtQueryKey(v75, 3i64, &qword_140028C50, 520i64, &TokenHandle);
      sub_140001010("Failed to query size of: %ws\\%ws\n\n", (char *)&qword_140028C50 + 6, L"IE Installed Date");
    }
    else
    {
      v76 = (BYTE *)j__malloc_base(cbData);
      if ( v76 )
      {
        v77 = cbData;
        for ( ii = 0; ii < cbData; v77 = cbData )
        {
          v79 = rand();
          v80 = ii++;
          v76[v80] = v79;
        }
        RegSetValueExW(v75, L"IE Installed Date", 0, 3u, v76, v77);
        free(v76);
        LODWORD(TokenHandle) = 520;
        sub_140007460(&qword_140028C50, 0i64, 520i64);
        NtQueryKey(v75, 3i64, &qword_140028C50, 520i64, &TokenHandle);
        LODWORD(ReturnLengthg) = cbData;
        LODWORD(PreviousStatef) = 196;
        sub_140001010(
          "%ws\\%ws\n%c%c binary of length %d\n\n",
          (char *)&qword_140028C50 + 6,
          L"IE Installed Date",
          192i64,
          PreviousStatef,
          ReturnLengthg);
      }
      else
      {
        sub_140001010("Failed to allocate buffer for SpoofBinary\n\n");
      }
    }
    RegCloseKey(v75);
  }
  hkey = 0i64;
  if ( RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\SQMClient", 0, 0xF003Fu, &hkey) )
  {
    LODWORD(TokenHandle) = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
    sub_140001010("Failed to open key: %ws\\%ws\n\n", (char *)&qword_140028C50 + 6, L"SOFTWARE\\Microsoft\\SQMClient");
  }
  else
  {
    v81 = hkey;
    sub_140007460(&FindFileData, 0i64, 520i64);
    sub_1400050D0(v81, L"MachineId", (BYTE *)&FindFileData);
    RegCloseKey(v81);
  }
  sub_140005580(-2147483646i64, L"SOFTWARE\\Microsoft\\SQMClient", L"WinSqmFirstSessionStartTime");
  sub_140005580(-2147483646i64, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"InstallTime");
  sub_140005580(-2147483646i64, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"InstallDate");
  hkey = 0i64;
  if ( RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, 0xF003Fu, &hkey) )
  {
    LODWORD(TokenHandle) = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
  }
  else
  {
    v82 = hkey;
    cbData = 0;
    if ( RegQueryValueExW(hkey, L"DigitalProductId", 0i64, 0i64, 0i64, &cbData) )
    {
      LODWORD(TokenHandle) = 520;
      sub_140007460(&qword_140028C50, 0i64, 520i64);
      NtQueryKey(v82, 3i64, &qword_140028C50, 520i64, &TokenHandle);
      sub_140001010("Failed to query size of: %ws\\%ws\n\n", (char *)&qword_140028C50 + 6, L"DigitalProductId");
    }
    else
    {
      v83 = (BYTE *)j__malloc_base(cbData);
      if ( v83 )
      {
        v84 = cbData;
        for ( jj = 0; jj < cbData; v84 = cbData )
        {
          v86 = rand();
          v87 = jj++;
          v83[v87] = v86;
        }
        RegSetValueExW(v82, L"DigitalProductId", 0, 3u, v83, v84);
        free(v83);
        LODWORD(TokenHandle) = 520;
        sub_140007460(&qword_140028C50, 0i64, 520i64);
        NtQueryKey(v82, 3i64, &qword_140028C50, 520i64, &TokenHandle);
        LODWORD(ReturnLengthh) = cbData;
        LODWORD(PreviousStateg) = 196;
        sub_140001010(
          "%ws\\%ws\n%c%c binary of length %d\n\n",
          (char *)&qword_140028C50 + 6,
          L"DigitalProductId",
          192i64,
          PreviousStateg,
          ReturnLengthh);
      }
      else
      {
        sub_140001010("Failed to allocate buffer for SpoofBinary\n\n");
      }
    }
    RegCloseKey(v82);
  }
  hkey = 0i64;
  if ( RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, 0xF003Fu, &hkey) )
  {
    LODWORD(TokenHandle) = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
  }
  else
  {
    v88 = hkey;
    cbData = 0;
    if ( RegQueryValueExW(hkey, L"DigitalProductId4", 0i64, 0i64, 0i64, &cbData) )
    {
      LODWORD(TokenHandle) = 520;
      sub_140007460(&qword_140028C50, 0i64, 520i64);
      NtQueryKey(v88, 3i64, &qword_140028C50, 520i64, &TokenHandle);
      sub_140001010("Failed to query size of: %ws\\%ws\n\n", (char *)&qword_140028C50 + 6, L"DigitalProductId4");
    }
    else
    {
      v89 = (BYTE *)j__malloc_base(cbData);
      if ( v89 )
      {
        v90 = cbData;
        for ( kk = 0; kk < cbData; v90 = cbData )
        {
          v92 = rand();
          v93 = kk++;
          v89[v93] = v92;
        }
        RegSetValueExW(v88, L"DigitalProductId4", 0, 3u, v89, v90);
        free(v89);
        LODWORD(TokenHandle) = 520;
        sub_140007460(&qword_140028C50, 0i64, 520i64);
        NtQueryKey(v88, 3i64, &qword_140028C50, 520i64, &TokenHandle);
        LODWORD(ReturnLengthi) = cbData;
        LODWORD(PreviousStateh) = 196;
        sub_140001010(
          "%ws\\%ws\n%c%c binary of length %d\n\n",
          (char *)&qword_140028C50 + 6,
          L"DigitalProductId4",
          192i64,
          PreviousStateh,
          ReturnLengthi);
      }
      else
      {
        sub_140001010("Failed to allocate buffer for SpoofBinary\n\n");
      }
    }
    RegCloseKey(v88);
  }
  hkey = 0i64;
  if ( RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, 0xF003Fu, &hkey) )
  {
    LODWORD(TokenHandle) = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
  }
  else
  {
    v94 = hkey;
    sub_140007460(&FindFileData, 0i64, 520i64);
    sub_1400050D0(v94, L"BuildGUID", (BYTE *)&FindFileData);
    RegCloseKey(v94);
  }
  hkey = 0i64;
  if ( RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, 0xF003Fu, &hkey) )
  {
    LODWORD(TokenHandle) = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
  }
  else
  {
    v95 = hkey;
    sub_140007460(&FindFileData, 0i64, 520i64);
    sub_1400050D0(v95, L"ProductId", (BYTE *)&FindFileData);
    RegCloseKey(v95);
  }
  hkey = 0i64;
  if ( RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, 0xF003Fu, &hkey) )
  {
    LODWORD(TokenHandle) = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
  }
  else
  {
    v96 = hkey;
    sub_140007460(&FindFileData, 0i64, 520i64);
    sub_1400050D0(v96, L"BuildLab", (BYTE *)&FindFileData);
    RegCloseKey(v96);
  }
  hkey = 0i64;
  if ( RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, 0xF003Fu, &hkey) )
  {
    LODWORD(TokenHandle) = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
  }
  else
  {
    v97 = hkey;
    sub_140007460(&FindFileData, 0i64, 520i64);
    sub_1400050D0(v97, L"BuildLabEx", (BYTE *)&FindFileData);
    RegCloseKey(v97);
  }
  hkey = 0i64;
  if ( RegOpenKeyExW(
         HKEY_LOCAL_MACHINE,
         L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000",
         0,
         0xF003Fu,
         &hkey) )
  {
    LODWORD(TokenHandle) = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000");
  }
  else
  {
    v98 = hkey;
    sub_140007460(&FindFileData, 0i64, 520i64);
    sub_1400050D0(v98, L"_DriverProviderInfo", (BYTE *)&FindFileData);
    RegCloseKey(v98);
  }
  hkey = 0i64;
  if ( RegOpenKeyExW(
         HKEY_LOCAL_MACHINE,
         L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000",
         0,
         0xF003Fu,
         &hkey) )
  {
    LODWORD(TokenHandle) = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000");
  }
  else
  {
    v99 = hkey;
    sub_140007460(&FindFileData, 0i64, 520i64);
    sub_1400050D0(v99, L"UserModeDriverGUID", (BYTE *)&FindFileData);
    RegCloseKey(v99);
  }
  hkey = 0i64;
  if ( RegOpenKeyExW(
         HKEY_LOCAL_MACHINE,
         L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}",
         0,
         0xF003Fu,
         &hkey) )
  {
    LODWORD(TokenHandle) = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
    sub_140001010(
      "Failed to open key: %ws\\%ws\n\n",
      (char *)&qword_140028C50 + 6,
      L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}");
  }
  else
  {
    v100 = hkey;
    sub_140007460(pszSubKey, 0i64, 520i64);
    v101 = 0;
    for ( LODWORD(phkResult) = 520;
          !RegEnumKeyExW(v100, v101, pszSubKey, (LPDWORD)&phkResult, 0i64, 0i64, 0i64, 0i64);
          LODWORD(phkResult) = 520 )
    {
      if ( stricmp((const char *)pszSubKey, L"configuration") && stricmp((const char *)pszSubKey, L"properties") )
      {
        v102 = SHDeleteValueW(v100, pszSubKey, L"NetworkAddress");
        if ( v102 != 2 )
        {
          LODWORD(TokenHandle) = 520;
          if ( v102 )
          {
            sub_140007460(&qword_140028C50, 0i64, 520i64);
            NtQueryKey(v100, 3i64, &qword_140028C50, 520i64, &TokenHandle);
            sub_140001010(
              "Failed to delete value: %ws\\%ws\\%ws\n\n",
              (char *)&qword_140028C50 + 6,
              pszSubKey,
              L"NetworkAddress");
          }
          else
          {
            sub_140007460(&qword_140028C50, 0i64, 520i64);
            NtQueryKey(v100, 3i64, &qword_140028C50, 520i64, &TokenHandle);
            LODWORD(ReturnLength) = 196;
            LODWORD(PreviousStatei) = 192;
            sub_140001010(
              "%ws\\%ws\\%ws\n%c%c deleted\n\n",
              (char *)&qword_140028C50 + 6,
              pszSubKey,
              L"NetworkAddress",
              PreviousStatei,
              ReturnLength);
          }
        }
        sub_140005580(v100, pszSubKey, L"NetworkInterfaceInstallTimestamp");
      }
      ++v101;
    }
    RegCloseKey(v100);
  }
  sub_140005B90(
    -2147483646i64,
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SettingsRequests");
  sub_140005580(
    -2147483646i64,
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SevilleEventlogManager",
    L"LastEventlogWrittenTime");
  sub_140005580(
    -2147483646i64,
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform\\Activation",
    L"ProductActivationTime");
  v103 = SHDeleteValueW(
           HKEY_LOCAL_MACHINE,
           L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform",
           L"BackupProductKeyDefault");
  if ( v103 != 2 )
  {
    LODWORD(TokenHandle) = 520;
    if ( v103 )
    {
      sub_140007460(&qword_140028C50, 0i64, 520i64);
      NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
      sub_140001010(
        "Failed to delete value: %ws\\%ws\\%ws\n\n",
        (char *)&qword_140028C50 + 6,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform",
        L"BackupProductKeyDefault");
    }
    else
    {
      sub_140007460(&qword_140028C50, 0i64, 520i64);
      NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
      LODWORD(ReturnLength) = 196;
      LODWORD(PreviousStatej) = 192;
      sub_140001010(
        "%ws\\%ws\\%ws\n%c%c deleted\n\n",
        (char *)&qword_140028C50 + 6,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform",
        L"BackupProductKeyDefault",
        PreviousStatej,
        ReturnLength);
    }
  }
  v104 = SHDeleteValueW(
           HKEY_LOCAL_MACHINE,
           L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform",
           L"actionlist");
  if ( v104 != 2 )
  {
    LODWORD(TokenHandle) = 520;
    if ( v104 )
    {
      sub_140007460(&qword_140028C50, 0i64, 520i64);
      NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
      sub_140001010(
        "Failed to delete value: %ws\\%ws\\%ws\n\n",
        (char *)&qword_140028C50 + 6,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform",
        L"actionlist");
    }
    else
    {
      sub_140007460(&qword_140028C50, 0i64, 520i64);
      NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
      LODWORD(ReturnLength) = 196;
      LODWORD(PreviousStatek) = 192;
      sub_140001010(
        "%ws\\%ws\\%ws\n%c%c deleted\n\n",
        (char *)&qword_140028C50 + 6,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform",
        L"actionlist",
        PreviousStatek,
        ReturnLength);
    }
  }
  v105 = SHDeleteValueW(
           HKEY_LOCAL_MACHINE,
           L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform",
           L"ServiceSessionId");
  if ( v105 != 2 )
  {
    LODWORD(TokenHandle) = 520;
    if ( v105 )
    {
      sub_140007460(&qword_140028C50, 0i64, 520i64);
      NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
      sub_140001010(
        "Failed to delete value: %ws\\%ws\\%ws\n\n",
        (char *)&qword_140028C50 + 6,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform",
        L"ServiceSessionId");
    }
    else
    {
      sub_140007460(&qword_140028C50, 0i64, 520i64);
      NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
      LODWORD(ReturnLength) = 196;
      LODWORD(PreviousStatel) = 192;
      sub_140001010(
        "%ws\\%ws\\%ws\n%c%c deleted\n\n",
        (char *)&qword_140028C50 + 6,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform",
        L"ServiceSessionId",
        PreviousStatel,
        ReturnLength);
    }
  }
  sub_140005B90(-2147483647i64, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist");
  sub_140005B90(-2147483647i64, L"Software\\Hex-Rays\\IDA\\History");
  sub_140005B90(-2147483647i64, L"Software\\Hex-Rays\\IDA\\History64");
  hkey = 0i64;
  if ( RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\UEFI\\ESRT", 0, 0xF003Fu, &hkey) )
  {
    LODWORD(TokenHandle) = 520;
    sub_140007460(&qword_140028C50, 0i64, 520i64);
    NtQueryKey(-2147483646i64, 3i64, &qword_140028C50, 520i64, &TokenHandle);
    sub_140001010("Failed to open key: %ws\\%ws\n\n", (char *)&qword_140028C50 + 6, L"HARDWARE\\UEFI\\ESRT");
  }
  else
  {
    v106 = hkey;
    sub_140007460(&v184, 0i64, 132600i64);
    v107 = 0;
    sub_140007460(v179, 0i64, 520i64);
    v108 = 0;
    LODWORD(phkResult) = 520;
    if ( !RegEnumKeyExW(v106, 0, v179, (LPDWORD)&phkResult, 0i64, 0i64, 0i64, 0i64) )
    {
      do
      {
        v109 = 260i64 * v107++;
        v110 = v179;
        do
        {
          v111 = *v110;
          v110[v109 + 1320] = *v110;
          ++v110;
        }
        while ( v111 );
        ++v108;
        LODWORD(phkResult) = 520;
      }
      while ( !RegEnumKeyExW(v106, v108, v179, (LPDWORD)&phkResult, 0i64, 0i64, 0i64, 0i64) );
      if ( v107 )
      {
        v112 = v107;
        v113 = -3168i64;
        v114 = &v184;
        do
        {
          sub_140007460(pszSubKey, 0i64, 520i64);
          v115 = v114;
          do
          {
            v116 = v115->dwFileAttributes;
            *(_WORD *)((char *)&v115->dwFileAttributes + v113) = v115->dwFileAttributes;
            v115 = (struct _WIN32_FIND_DATAW *)((char *)v115 + 2);
          }
          while ( v116 );
          v117 = 0;
          v118 = -1i64;
          do
            ++v118;
          while ( pszSubKey[v118] );
          if ( v118 )
          {
            v119 = 0i64;
            do
            {
              v120 = &pszSubKey[v119];
              if ( (unsigned int)sub_14000A64C(*v120, 128i64) )
              {
                v121 = rand();
                v122 = -1i64;
                do
                  ++v122;
                while ( aAbcdef01234578[v122] );
                *v120 = aAbcdef01234578[v121 % v122];
              }
              v119 = ++v117;
              v123 = -1i64;
              do
                ++v123;
              while ( pszSubKey[v123] );
            }
            while ( v117 < v123 );
          }
          sub_140005970(v106, (LPCWSTR)v114, pszSubKey);
          v114 = (struct _WIN32_FIND_DATAW *)((char *)v114 + 520);
          v113 -= 520i64;
          --v112;
        }
        while ( v112 );
      }
    }
    RegCloseKey(v106);
  }
  sub_140007460(FileName, 0i64, 520i64);
  sub_140007460(Buffer, 0i64, 520i64);
  sub_140007460(pszPath, 0i64, 520i64);
  sub_140007460(v181, 0i64, 520i64);
  GetTempPathW(0x104u, Buffer);
  SHGetFolderPathW(0i64, 26, 0i64, 1u, pszPath);
  SHGetFolderPathW(0i64, 28, 0i64, 1u, v181);
  wsprintfW(FileName, L"%ws*", Buffer);
  sub_140007460(&FindFileData, 0i64, 592i64);
  v124 = FindFirstFileW(FileName, &FindFileData);
  do
  {
    if ( FindFileData.cFileName[0] != 46
      || FindFileData.cFileName[1] && (FindFileData.cFileName[1] != 46 || FindFileData.cFileName[2]) )
    {
      wsprintfW(FileName, L"%ws%ws", Buffer, FindFileData.cFileName);
      sub_140005D90(FileName);
    }
  }
  while ( FindNextFileW(v124, &FindFileData) );
  FindClose(v124);
  wsprintfW(FileName, L"%ws\\D3DSCache", v181);
  sub_140005D90(FileName);
  wsprintfW(FileName, L"%ws\\NVIDIA Corporation\\GfeSDK", v181);
  sub_140005D90(FileName);
  wsprintfW(FileName, L"%ws\\Microsoft\\Feeds", v181);
  sub_140005D90(FileName);
  wsprintfW(FileName, L"%ws\\Microsoft\\Feeds Cache", v181);
  sub_140005D90(FileName);
  wsprintfW(FileName, L"%ws\\Microsoft\\Windows\\INetCache", v181);
  sub_140005D90(FileName);
  wsprintfW(FileName, L"%ws\\Microsoft\\Windows\\INetCookies", v181);
  sub_140005D90(FileName);
  wsprintfW(FileName, L"%ws\\Microsoft\\Windows\\WebCache", v181);
  sub_140005D90(FileName);
  wsprintfW(FileName, L"%ws\\Microsoft\\XboxLive\\AuthStateCache.dat", v181);
  sub_140005D90(FileName);
  v125 = GetLogicalDrives();
  for ( ll = 67; v125; v125 >>= 1 )
  {
    if ( (v125 & 1) != 0 )
    {
      sub_140001010("\n-- DRIVE: %c --\n\n", ll);
      wsprintfW(FileName, L"\\\\.\\%c:", ll);
      v127 = CreateFileW(FileName, 0xC0000000, 3u, 0i64, 3u, 0x80u, 0i64);
      if ( v127 != (HANDLE)-1i64 )
      {
        sub_140007460(pszSubKey, 0i64, 512i64);
        Luid.LowPart = 0;
        if ( ReadFile(v127, pszSubKey, 0x200u, (LPDWORD)&Luid, 0i64) && Luid.LowPart == 512 )
        {
          v128 = 0;
          v129 = &off_140027A50;
          while ( 1 )
          {
            v130 = *v129;
            v131 = -1i64;
            do
              ++v131;
            while ( v130[v131] );
            if ( !memcmp((char *)pszSubKey + *((unsigned int *)v129 + 2), v130, v131) )
              break;
            ++v128;
            v129 += 2;
            if ( v128 >= 3 )
              goto LABEL_275;
          }
          v132 = rand() << 16;
          *(_DWORD *)((char *)pszSubKey + *((unsigned int *)v129 + 3)) = rand() + v132;
          if ( SetFilePointer(v127, 0, 0i64, 0) != -1 )
            WriteFile(v127, pszSubKey, 0x200u, 0i64, 0i64);
        }
LABEL_275:
        CloseHandle(v127);
      }
      wsprintfW(FileName, L"%c:\\Windows\\System32\\restore\\MachineGuid.txt", ll);
      sub_140005D90(FileName);
      wsprintfW(FileName, L"%c:\\Users\\Public\\Libraries\\collection.dat", ll);
      sub_140005D90(FileName);
      wsprintfW(FileName, L"%c:\\System Volume Information\\IndexerVolumeGuid", ll);
      sub_140005D90(FileName);
      wsprintfW(FileName, L"%c:\\System Volume Information\\WPSettings.dat", ll);
      sub_140005D90(FileName);
      wsprintfW(FileName, L"%c:\\System Volume Information\\tracking.log", ll);
      sub_140005D90(FileName);
      wsprintfW(FileName, L"%c:\\ProgramData\\Microsoft\\Windows\\WER", ll);
      sub_140005D90(FileName);
      wsprintfW(FileName, L"%c:\\Users\\Public\\Shared Files", ll);
      sub_140005D90(FileName);
      wsprintfW(FileName, L"%c:\\Windows\\INF\\setupapi.dev.log", ll);
      sub_140005D90(FileName);
      wsprintfW(FileName, L"%c:\\Windows\\INF\\setupapi.setup.log", ll);
      sub_140005D90(FileName);
      wsprintfW(FileName, L"%c:\\Windows\\System32\\spp\\store", ll);
      sub_140005D90(FileName);
      wsprintfW(FileName, L"%c:\\Users\\Public\\Libraries", ll);
      sub_140005D90(FileName);
      wsprintfW(FileName, L"%c:\\MSOCache", ll);
      sub_140005D90(FileName);
      wsprintfW(FileName, L"%c:\\ProgramData\\ntuser.pol", ll);
      sub_140005D90(FileName);
      wsprintfW(FileName, L"%c:\\Users\\Default\\NTUSER.DAT", ll);
      sub_140005D90(FileName);
      wsprintfW(FileName, L"%c:\\Recovery\\ntuser.sys", ll);
      sub_140005D90(FileName);
      wsprintfW(FileName, L"%c:\\desktop.ini", ll);
      sub_140005D90(FileName);
      wsprintfW(FileName, L"%c:\\Windows\\Prefetch\\*", ll);
      sub_140007460(&v184, 0i64, 592i64);
      v133 = FindFirstFileW(FileName, &v184);
      do
      {
        if ( v184.cFileName[0] != 46 || v184.cFileName[1] && (v184.cFileName[1] != 46 || v184.cFileName[2]) )
        {
          wsprintfW(FileName, L"%c:\\Windows\\Prefetch\\%ws", ll, v184.cFileName);
          sub_140005D90(FileName);
        }
      }
      while ( FindNextFileW(v133, &v184) );
      FindClose(v133);
      wsprintfW(FileName, L"%c:\\Users\\*", ll);
      sub_140007460(&Name, 0i64, 592i64);
      v134 = FindFirstFileW(FileName, &Name);
      do
      {
        if ( (Name.cFileName[0] != 46 || Name.cFileName[1] && (Name.cFileName[1] != 46 || Name.cFileName[2]))
          && (Name.dwFileAttributes & 0x10) != 0 )
        {
          sub_140007460(v179, 0i64, 520i64);
          v135 = 0i64;
          do
          {
            v136 = Name.cFileName[v135];
            v179[v135++] = v136;
          }
          while ( v136 );
          wsprintfW(FileName, L"%c:\\Users\\%ws\\*", ll, v179);
          sub_140007460(&FindFileData, 0i64, 592i64);
          v137 = FindFirstFileW(FileName, &FindFileData);
          do
          {
            if ( FindFileData.cFileName[0] != 46
              || FindFileData.cFileName[1] && (FindFileData.cFileName[1] != 46 || FindFileData.cFileName[2]) )
            {
              if ( StrStrW(FindFileData.cFileName, L"ntuser") )
              {
                wsprintfW(FileName, L"%c:\\Users\\%ws\\%ws", ll, v179, FindFileData.cFileName);
                sub_140005D90(FileName);
              }
            }
          }
          while ( FindNextFileW(v137, &FindFileData) );
          FindClose(v137);
        }
      }
      while ( FindNextFileW(v134, &Name) );
      FindClose(v134);
      wsprintfW(FileName, L"%c:\\Users", ll);
      sub_1400060D0(FileName);
      sub_140007460(SubKey, 0i64, 260i64);
      sub_140001070((int)SubKey, (int)"fsutil usn deletejournal /d %c:");
      sub_14000A514(SubKey);
      ++ll;
    }
  }
  sub_14000A514("vssadmin delete shadows /All /Quiet");
  v138 = CreateToolhelp32Snapshot(2u, 0);
  if ( v138 )
  {
    sub_140007460(&FindFileData.ftCreationTime, 0i64, 564i64);
    FindFileData.dwFileAttributes = 568;
    if ( Process32FirstW(v138, (LPPROCESSENTRY32W)&FindFileData) )
    {
      while ( stricmp((const char *)FindFileData.cFileName, L"WmiPrvSE.exe") )
      {
        if ( !Process32NextW(v138, (LPPROCESSENTRY32W)&FindFileData) )
          goto LABEL_310;
      }
      v139 = OpenProcess(0x1FFFFFu, 0, FindFileData.ftCreationTime.dwHighDateTime);
      if ( v139 != (HANDLE)-1i64 )
      {
        sub_140001010("Killed Winmgmt\n");
        TerminateProcess(v139, 0);
        CloseHandle(v139);
      }
    }
LABEL_310:
    CloseHandle(v138);
  }
  sub_14000A514("net stop winmgmt /Y");
  sub_14000A514("pause");
  return 0;
}

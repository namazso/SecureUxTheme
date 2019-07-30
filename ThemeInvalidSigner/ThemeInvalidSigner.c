// SecureUxTheme - A secure boot compatible in-memory UxTheme patcher
// Copyright (C) 2019  namazso
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include <windows.h>
#include <wchar.h>

static HRESULT ResultFromKnownLastError(void)
{
  return HRESULT_FROM_WIN32(GetLastError());
}

static HRESULT /*CThemeSignature::*/ReadSignature(
  /*CThemeSignature *this,*/
  HANDLE file,
  PBYTE signature
)
{
  HRESULT result; // eax
  BOOLEAN v6; // cc
  DWORD NumberOfBytesRead; // [rsp+30h] [rbp-30h]
  LARGE_INTEGER DistanceToMove; // [rsp+38h] [rbp-28h]
  ULARGE_INTEGER FileSize; // [rsp+40h] [rbp-20h]
  DWORD Buffer[4]; // [rsp+48h] [rbp-18h]

  FileSize.LowPart = GetFileSize(file, &FileSize.HighPart);
  // Yes, this is indeed incorrect, you're supposed to check GetLastError(),
  // in case a file size's low DWORD just happens to be 0xFFFFFFFF. However,
  // since this error exists in the Windows implementation we should probably
  // consider such files invalid too. This way file size will be "fixed" by the
  // added invalid signature. And anyways, who wants 4 GB+ themes?
  if (FileSize.LowPart == INVALID_FILE_SIZE)
    return ResultFromKnownLastError();
  DistanceToMove.QuadPart = -16;
  if (SetFilePointer(file, DistanceToMove.LowPart, &DistanceToMove.HighPart, FILE_END) == INVALID_SET_FILE_POINTER)
  {
    result = GetLastError();
    v6 = result <= 0;
    if (result)
      goto LABEL_15;
  }
  if (!ReadFile(file, Buffer, 16u, &NumberOfBytesRead, 0))
    goto LABEL_14;
  if (NumberOfBytesRead != 16 || Buffer[0] != 0x84692426 || FileSize.QuadPart != *(PDWORD64)&Buffer[2])
    return 0x80004005;
  DistanceToMove.QuadPart = -16 - (LONGLONG)Buffer[1];
  if (SetFilePointer(file, DistanceToMove.LowPart, &DistanceToMove.HighPart, FILE_END) != INVALID_SET_FILE_POINTER
    || (result = GetLastError(), v6 = result <= 0, !result))
  {
    if (ReadFile(file, signature, 0x80u, &NumberOfBytesRead, NULL))
      return NumberOfBytesRead != 0x80 ? 0x80004005 : 0;
  LABEL_14:
    result = GetLastError();
    v6 = result <= 0;
  }
LABEL_15:
  if (!v6)
    result = (WORD)result | 0x80070000;
  return result;
}

static DWORD do_stuff(PCWSTR file_name)
{
  DWORD error = ERROR_SUCCESS;
  HANDLE file = INVALID_HANDLE_VALUE;
  WCHAR path[MAXSHORT] = L"\\\\?\\";
  BYTE signature[128];

  if(0 == GetFullPathNameW(
    file_name,
    _ARRAYSIZE(path) - 4,
    &path[4],
    NULL
  ))
  {
    error = GetLastError();
    goto cleanup;
  }

  file = CreateFileW(
    path,
    GENERIC_READ | GENERIC_WRITE,
    0,
    NULL,
    OPEN_ALWAYS,
    FILE_ATTRIBUTE_NORMAL,
    NULL
  );

  // check for a "valid" signature on the file
  HRESULT sig_test = ReadSignature(file, signature);
  if (!SUCCEEDED(sig_test))
  {
    ULARGE_INTEGER file_size;

    file_size.LowPart = GetFileSize(file, &file_size.HighPart);
    if (file_size.LowPart == INVALID_FILE_SIZE)
    {
      error = GetLastError();
      if (error != NO_ERROR)
        goto cleanup;
    }

    LARGE_INTEGER distance;
    distance.QuadPart = 0;

    if (SetFilePointer(file, distance.LowPart, &distance.HighPart, FILE_END) == INVALID_SET_FILE_POINTER)
    {
      error = GetLastError();
      if (error != NO_ERROR)
        goto cleanup;
    }

    DWORD written;
    ZeroMemory(signature, sizeof(signature));

    // write an invalid signature (all nulls)
    BOOL succeeded = WriteFile(
      file,
      signature,
      sizeof(signature),
      &written,
      NULL
    );

    if (!succeeded)
    {
      error = GetLastError();
      goto cleanup;
    }

    DWORD magic = 0x84692426;

    // write magic number for signature
    succeeded = WriteFile(
      file,
      &magic,
      sizeof(magic),
      &written,
      NULL
    );

    if (!succeeded)
    {
      error = GetLastError();
      goto cleanup;
    }

    DWORD negative_distance_from_magic = 0x80;

    // write the backwards distance of signature from magic
    succeeded = WriteFile(
      file,
      &negative_distance_from_magic,
      sizeof(negative_distance_from_magic),
      &written,
      NULL
    );

    if (!succeeded)
    {
      error = GetLastError();
      goto cleanup;
    }

    file_size.QuadPart += 0x80 + 4 + 4 + 8;

    // write new file size
    succeeded = WriteFile(
      file,
      &file_size,
      sizeof(file_size),
      &written,
      NULL
    );

    if (!succeeded)
    {
      error = GetLastError();
      goto cleanup;
    }
  }

cleanup:

  CloseHandle(file);

  return error;
}

int wmain(int argc, wchar_t *argv[], wchar_t *envp[])
{
  DWORD error = ERROR_SUCCESS;
  if (argc < 2)
  {
    wprintf(L"Usage: ThemeInvalidSigner <filename>\n");
    error = ERROR_INVALID_PARAMETER;
  }
  else
  {
    error = do_stuff(argv[1]);
  }

  WCHAR buf[1024];
  FormatMessageW(
    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL,
    error,
    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
    buf,
    _ARRAYSIZE(buf),
    NULL
  );

  wprintf(L"Result: %s", buf);
  return error;
}
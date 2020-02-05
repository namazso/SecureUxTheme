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

#include <Windows.h>
#include <wchar.h>

typedef struct _THEME_SIGNATURE_HEADER
{
  ULONG Magic;
  ULONG SignatureOffset;
  ULONGLONG FileSize;
} THEME_SIGNATURE_HEADER;

#define THEME_SIGNATURE_MAGIC ((ULONG)(0x84692426))
#define THEME_SIGNATURE_SIZE (128u)

static HRESULT ResultFromKnownLastError(void)
{
  return HRESULT_FROM_WIN32(GetLastError());
}

static HRESULT /*CThemeSignature::*/ReadSignature(
  /*CThemeSignature *this,*/
  HANDLE File,
  PBYTE Signature
)
{
  DWORD Result;
  DWORD NumberOfBytesRead;
  LARGE_INTEGER DistanceToMove;
  ULARGE_INTEGER FileSize;
  THEME_SIGNATURE_HEADER SignatureHeader;

  FileSize.LowPart = GetFileSize(File, &FileSize.HighPart);
  // Yes, this is indeed incorrect, you're supposed to check GetLastError(),
  // in case a file size's low DWORD just happens to be 0xFFFFFFFF. However,
  // since this error exists in the Windows implementation we should probably
  // consider such files invalid too. This way file size will be "fixed" by the
  // added invalid signature. And anyways, who wants 4 GB+ themes?
  if (FileSize.LowPart == INVALID_FILE_SIZE)
    return ResultFromKnownLastError();

  DistanceToMove.QuadPart = -(SSIZE_T)sizeof(SignatureHeader);
  if (SetFilePointer(File, DistanceToMove.LowPart, &DistanceToMove.HighPart, FILE_END) == INVALID_SET_FILE_POINTER)
    return ResultFromKnownLastError();

  if (!ReadFile(File, &SignatureHeader, sizeof(SignatureHeader), &NumberOfBytesRead, 0))
    return ResultFromKnownLastError();

  if (NumberOfBytesRead != sizeof(SignatureHeader) || SignatureHeader.Magic != THEME_SIGNATURE_MAGIC || FileSize.QuadPart != SignatureHeader.FileSize)
    return E_FAIL;

  DistanceToMove.QuadPart = -(SSIZE_T)sizeof(SignatureHeader) - (LONGLONG)SignatureHeader.SignatureOffset;
  if (SetFilePointer(File, DistanceToMove.LowPart, &DistanceToMove.HighPart, FILE_END) == INVALID_SET_FILE_POINTER && ((Result = GetLastError())))
    return HRESULT_FROM_WIN32(Result);

  if (!ReadFile(File, Signature, THEME_SIGNATURE_SIZE, &NumberOfBytesRead, NULL))
    return ResultFromKnownLastError();
  
  return NumberOfBytesRead != THEME_SIGNATURE_SIZE ? E_FAIL : NOERROR;
}

static DWORD do_stuff(PCWSTR file_name)
{
  DWORD error = ERROR_SUCCESS;
  HANDLE file;
  WCHAR path[MAXSHORT] = L"\\\\?\\";
  BYTE signature[THEME_SIGNATURE_SIZE];
  ULARGE_INTEGER file_size;
  LARGE_INTEGER distance;
  THEME_SIGNATURE_HEADER signature_header;
  DWORD bytes_written;
  BOOLEAN succeeded;

  if(0 == GetFullPathNameW(
    file_name,
    _ARRAYSIZE(path) - 4,
    &path[4],
    NULL
  ))
  {
    error = GetLastError();
    goto cleanup_nofile;
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

  if(file == INVALID_HANDLE_VALUE)
  {
    error = GetLastError();
    goto cleanup_nofile;
  }

  // check for a "valid" signature on the file
  if (SUCCEEDED(ReadSignature(file, signature)))
  {
    // There is a valid signature on the file already
    error = ERROR_SUCCESS;
    goto cleanup;
  }
  
  if ((file_size.LowPart = GetFileSize(file, &file_size.HighPart)) == INVALID_FILE_SIZE)
    if ((error = GetLastError()) != ERROR_SUCCESS)
      goto cleanup;

  distance.QuadPart = 0;
  if (SetFilePointer(file, distance.LowPart, &distance.HighPart, FILE_END) == INVALID_SET_FILE_POINTER)
    if ((error = GetLastError()) != ERROR_SUCCESS)
      goto cleanup;

  signature_header.Magic = THEME_SIGNATURE_MAGIC;
  signature_header.SignatureOffset = THEME_SIGNATURE_SIZE; // We might aswell just let random data be the signature
  signature_header.FileSize = file_size.QuadPart + sizeof(THEME_SIGNATURE_HEADER);
  succeeded = WriteFile(
    file,
    &signature_header,
    sizeof(signature_header),
    &bytes_written,
    NULL
  );

  if (!succeeded || bytes_written != sizeof(signature_header))
  {
    error = GetLastError();
    goto cleanup;
  }

cleanup:
  CloseHandle(file);

cleanup_nofile:
  return error;
}

int wmain(int argc, wchar_t *argv[], wchar_t *envp[])
{
  DWORD error = ERROR_SUCCESS;
  WCHAR buf[1024];

  if (argc < 2)
  {
    wprintf(L"Usage: ThemeInvalidSigner <filename>\n");
    error = ERROR_INVALID_PARAMETER;
  }
  else
  {
    error = do_stuff(argv[1]);
  }

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
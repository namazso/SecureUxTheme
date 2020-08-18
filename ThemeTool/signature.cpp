// SecureUxTheme - A secure boot compatible in-memory UxTheme patcher
// Copyright (C) 2020  namazso
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
#include "pch.h"

#include "signature.h"

typedef struct _THEME_SIGNATURE_HEADER
{
  ULONG Magic;
  ULONG SignatureOffset;
  ULONGLONG FileSize;
} THEME_SIGNATURE_HEADER;

constexpr static auto k_signature_magic = (ULONG)0x84692426;
constexpr static auto k_signature_size = 128u;

static HRESULT ResultFromKnownLastError()
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

  if (!ReadFile(File, &SignatureHeader, sizeof(SignatureHeader), &NumberOfBytesRead, nullptr))
    return ResultFromKnownLastError();

  if (NumberOfBytesRead != sizeof(SignatureHeader) || SignatureHeader.Magic != k_signature_magic || FileSize.QuadPart != SignatureHeader.FileSize)
    return E_FAIL;

  DistanceToMove.QuadPart = -(SSIZE_T)sizeof(SignatureHeader) - (LONGLONG)SignatureHeader.SignatureOffset;
  if (SetFilePointer(File, DistanceToMove.LowPart, &DistanceToMove.HighPart, FILE_END) == INVALID_SET_FILE_POINTER && ((Result = GetLastError())))
    return HRESULT_FROM_WIN32(Result);

  if (!ReadFile(File, Signature, k_signature_size, &NumberOfBytesRead, nullptr))
    return ResultFromKnownLastError();

  return NumberOfBytesRead != k_signature_size ? E_FAIL : NOERROR;
}

static HRESULT WriteSignature(
  HANDLE file
)
{
  ULARGE_INTEGER file_size;
  if ((file_size.LowPart = GetFileSize(file, &file_size.HighPart)) == INVALID_FILE_SIZE)
    if (const auto error = GetLastError())
      return HRESULT_FROM_WIN32(error);

  LARGE_INTEGER distance;
  distance.QuadPart = 0;
  if (SetFilePointer(file, distance.LowPart, &distance.HighPart, FILE_END) == INVALID_SET_FILE_POINTER)
    if (const auto error = GetLastError())
      return HRESULT_FROM_WIN32(error);

  THEME_SIGNATURE_HEADER signature_header;
  signature_header.Magic = k_signature_magic;
  // We might as well just let random data be the signature
  signature_header.SignatureOffset = k_signature_size;
  signature_header.FileSize = file_size.QuadPart + sizeof(THEME_SIGNATURE_HEADER);

  DWORD bytes_written{};
  const auto succeeded = WriteFile(
    file,
    &signature_header,
    sizeof(signature_header),
    &bytes_written,
    nullptr
  );

  return succeeded && bytes_written == sizeof(signature_header) ? NOERROR : ResultFromKnownLastError();
}

static HANDLE open_file(PCTSTR file_name, bool write)
{
  auto file = INVALID_HANDLE_VALUE;
  WCHAR path[MAXSHORT] = L"\\\\?\\";

  if (GetFullPathNameW(
    file_name,
    _ARRAYSIZE(path) - 4,
    &path[4],
    nullptr
  ))
  {
    file = CreateFileW(
      path,
      GENERIC_READ | (write ? GENERIC_WRITE : 0),
      0,
      nullptr,
      OPEN_ALWAYS,
      FILE_ATTRIBUTE_NORMAL,
      nullptr
    );
  }

  return file;
}

HRESULT sig::check_file(LPCWSTR path)
{
  const auto file = open_file(path, false);
  if(file == INVALID_HANDLE_VALUE)
    return ResultFromKnownLastError();

  BYTE signature[k_signature_size];
  const auto hr = ReadSignature(file, signature);
  CloseHandle(file);
  return hr;
}

HRESULT sig::fix_file(LPCWSTR path)
{
  if (SUCCEEDED(check_file(path)))
    return NOERROR;

  const auto file = open_file(path, true);
  if (file == INVALID_HANDLE_VALUE)
    return ResultFromKnownLastError();

  const auto hr = WriteSignature(file);
  CloseHandle(file);
  return hr;
}

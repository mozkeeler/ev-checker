/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <fstream>
#include <iostream>

#include "EVCheckerTrustDomain.h"
#include "nss.h"
#include "prerror.h"

void
PrintPRError(const char* message)
{
  const char* err = PR_ErrorToName(PR_GetError());
  if (err) {
    std::cerr << message << ":" << err << std::endl;
  } else {
    std::cerr << message << std::endl;
  }
}

void
PrintUsage(const char* argv0)
{
  std::cerr << "Usage: " << argv0 << " <end-entity certificate>" << std::endl;
}

inline void
SECITEM_FreeItem_true(SECItem* item)
{
  SECITEM_FreeItem(item, true);
}

typedef mozilla::pkix::ScopedPtr<SECItem, SECITEM_FreeItem_true> ScopedSECItem;

SECItem*
ReadFile(const char* filename)
{
  std::ifstream file(filename, std::ios::binary);
  std::streampos begin(file.tellg());
  file.seekg(0, std::ios::end);
  std::streampos end(file.tellg());
  size_t length = (end - begin);
  file.seekg(0, std::ios::beg);

  SECItem* data = SECITEM_AllocItem(nullptr, nullptr, length);
  if (!data) {
    PrintPRError("SECITEM_AllocItem failed");
    return nullptr;
  }
  file.read(reinterpret_cast<char *>(data->data), length);
  file.close();
  return data;
}

CERTCertificate*
ReadCertFromFile(const char* filename)
{
  ScopedSECItem der(ReadFile(filename));
  if (!der) {
    return nullptr;
  }
  CERTCertificate* cert = CERT_NewTempCertificate(CERT_GetDefaultCertDB(),
                                                  der.get(), nullptr, false,
                                                  true);
  if (!cert) {
    PrintPRError("CERT_NewTempCertificate failed");
    return nullptr;
  }
  return cert;
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    PrintUsage(argv[0]);
    return 1;
  }
  if (NSS_NoDB_Init(nullptr) != SECSuccess) {
    PrintPRError("NSS_NoDB_Init failed");
  }
  mozilla::pkix::ScopedCERTCertificate cert(ReadCertFromFile(argv[1]));
  return 0;
}

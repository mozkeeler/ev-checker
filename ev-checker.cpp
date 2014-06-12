/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <fstream>
#include <iostream>

#include "EVCheckerTrustDomain.h"
#include "nss.h"
#include "plbase64.h"
#include "plgetopt.h"
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
  std::cerr << "Usage: " << argv0 << " <-e end-entity certificate>";
  std::cerr << " <-r root certificate>" << std::endl;
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

static const char PEM_HEADER[] = "-----BEGIN CERTIFICATE-----";
static const char PEM_FOOTER[] = "-----END CERTIFICATE-----";

SECItem*
PEM2Base64(const SECItem* pem)
{
  if (pem->len < strlen(PEM_HEADER) ||
      (memcmp(pem->data, PEM_HEADER, strlen(PEM_HEADER)) != 0)) {
    return nullptr;
  }
  ScopedSECItem base64(SECITEM_AllocItem(nullptr, nullptr, pem->len));
  if (!base64) {
    PrintPRError("SECITEM_AllocItem failed");
    return nullptr;
  }
  size_t sindex = strlen(PEM_HEADER); // source index
  size_t dindex = 0; // destination index
  while (sindex < pem->len - strlen(PEM_FOOTER)) {
    if (!memcmp(pem->data + sindex, PEM_FOOTER, strlen(PEM_FOOTER))) {
      break;
    }
    if (pem->data[sindex] == '\r' || pem->data[sindex] == '\n') {
      sindex++;
      continue;
    }
    base64->data[dindex] = pem->data[sindex];
    dindex++;
    sindex++;
  }
  base64->data[dindex] = 0;
  base64->len = dindex;
  return base64.release();
}

CERTCertificate*
ReadCertFromFile(const char* filename)
{
  ScopedSECItem der(ReadFile(filename));
  if (!der) {
    return nullptr;
  }

  if (der->len > strlen(PEM_HEADER) &&
      !memcmp(der->data, PEM_HEADER, strlen(PEM_HEADER))) {
    ScopedSECItem base64(PEM2Base64(der.get()));
    if (!base64) {
      return nullptr;
    }
    if (!PL_Base64Decode(reinterpret_cast<const char*>(base64->data),
                         base64->len,
                         reinterpret_cast<char*>(der->data))) {
      PrintPRError("PL_Base64Decode failed");
      return nullptr;
    }
    size_t lengthAdjustment = 0;
    if (base64->len > 0 && base64->data[base64->len - 1] == '=') {
      lengthAdjustment++;
    }
    if (base64->len > 1 && base64->data[base64->len - 2] == '=') {
      lengthAdjustment++;
    }
    der->len = (base64->len * 3) / 4  - lengthAdjustment;
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

typedef mozilla::pkix::ScopedPtr<PLOptState, PL_DestroyOptState> ScopedPLOptState;

int main(int argc, char* argv[]) {
  if (argc < 5) {
    PrintUsage(argv[0]);
    return 1;
  }
  if (NSS_NoDB_Init(nullptr) != SECSuccess) {
    PrintPRError("NSS_NoDB_Init failed");
  }
  const char* endEntityFileName = nullptr;
  const char* rootFileName = nullptr;
  ScopedPLOptState opt(PL_CreateOptState(argc, argv, "e:r:"));
  PLOptStatus os;
  while ((os = PL_GetNextOpt(opt.get())) != PL_OPT_EOL) {
    if (os == PL_OPT_BAD) {
      continue;
    }
    switch (opt->option) {
      case 'e':
        endEntityFileName = opt->value;
        break;
      case 'r':
        rootFileName = opt->value;
        break;
      default:
        PrintUsage(argv[0]);
        return 1;
    }
  }
  if (!endEntityFileName || !rootFileName) {
    PrintUsage(argv[0]);
    return 1;
  }
  EVCheckerTrustDomain trustDomain(ReadCertFromFile(rootFileName));
  mozilla::pkix::ScopedCERTCertificate cert(ReadCertFromFile(endEntityFileName));
  mozilla::pkix::ScopedCERTCertList results;
  SECStatus rv = BuildCertChain(trustDomain, cert.get(), PR_Now(),
                                mozilla::pkix::EndEntityOrCA::MustBeEndEntity,
                                0,
                                mozilla::pkix::KeyPurposeId::anyExtendedKeyUsage,
                                mozilla::pkix::CertPolicyId::anyPolicy, nullptr,
                                results);
  if (rv != SECSuccess) {
    PrintPRError("BuildCertChain failed");
    return 1;
  }

  std::cout << "Success!" << std::endl;
  return 0;
}

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <curl/curl.h>

#include "EVCheckerTrustDomain.h"

#include "Util.h"
#include "prerror.h"
#include "secerr.h"
#include "ocsp.h"

using namespace mozilla::pkix;

EVCheckerTrustDomain::EVCheckerTrustDomain(CERTCertificate* root)
 : mRoot(root)
{
}

typedef mozilla::pkix::ScopedPtr<CERTCertificatePolicies,
                                 CERT_DestroyCertificatePoliciesExtension>
                                 ScopedCERTCertificatePolicies;
// Largely informed by
// <mozilla-central>/security/certverifier/ExtendedValidation.cpp
SECStatus
EVCheckerTrustDomain::GetFirstEVPolicyForCert(const CERTCertificate* cert,
  /*out*/ mozilla::pkix::CertPolicyId& policy)
{
  if (!cert->extensions) {
    PR_SetError(SEC_ERROR_EXTENSION_NOT_FOUND, 0);
    return SECFailure;
  }

  for (size_t i = 0; cert->extensions[i]; i++) {
    const SECItem* oid = &cert->extensions[i]->id;
    SECOidTag oidTag = SECOID_FindOIDTag(oid);
    if (oidTag != SEC_OID_X509_CERTIFICATE_POLICIES) {
      continue;
    }
    const SECItem* value = &cert->extensions[i]->value;
    ScopedCERTCertificatePolicies policies(
      CERT_DecodeCertificatePoliciesExtension(value));
    if (!policies) {
      continue;
    }
    for (CERTPolicyInfo** policyInfos = policies->policyInfos;
         *policyInfos; policyInfos++) {
      const CERTPolicyInfo* policyInfo = *policyInfos;
      SECOidTag oidTag = policyInfo->oid;
      if (oidTag == mEVPolicyOIDTag) {
        const SECOidData* oidData = SECOID_FindOIDByTag(oidTag);
        if (oidData && oidData->oid.data && oidData->oid.len > 0 &&
            oidData->oid.len <= mozilla::pkix::CertPolicyId::MAX_BYTES) {
          policy.numBytes = static_cast<uint16_t>(oidData->oid.len);
          memcpy(policy.bytes, oidData->oid.data, policy.numBytes);
          return SECSuccess;
        }
      }
    }

  }

  PR_SetError(SEC_ERROR_EXTENSION_NOT_FOUND, 0);
  return SECFailure;
}


SECStatus
EVCheckerTrustDomain::Init(const char* dottedEVPolicyOID,
                           const char* evPolicyName)
{
  SECItem evOIDItem = { siBuffer, 0, 0 };
  if (SEC_StringToOID(nullptr, &evOIDItem, dottedEVPolicyOID, 0)
        != SECSuccess) {
    PrintPRError("SEC_StringToOID failed");
    return SECFailure;
  }
  SECOidData oidData;
  oidData.oid.len = evOIDItem.len;
  oidData.oid.data = evOIDItem.data;
  oidData.offset = SEC_OID_UNKNOWN;
  oidData.desc = evPolicyName;
  oidData.mechanism = CKM_INVALID_MECHANISM;
  oidData.supportedExtension = INVALID_CERT_EXTENSION;
  mEVPolicyOIDTag = SECOID_AddEntry(&oidData);
  PORT_Free(evOIDItem.data);

  if (mEVPolicyOIDTag == SEC_OID_UNKNOWN) {
    PR_SetError(SEC_ERROR_INVALID_ARGS, 0);
    return SECFailure;
  }
  return SECSuccess;
}

SECStatus
EVCheckerTrustDomain::GetCertTrust(EndEntityOrCA endEntityOrCA,
                                   const CertPolicyId& policy,
                                   const SECItem& candidateCertDER,
                           /*out*/ TrustLevel* trustLevel)
{
  if (SECITEM_ItemsAreEqual(&candidateCertDER, &mRoot->derCert)) {
    *trustLevel = TrustLevel::TrustAnchor;
  } else {
    *trustLevel = TrustLevel::InheritsTrust;
  }
  return SECSuccess;
}

SECStatus
EVCheckerTrustDomain::FindPotentialIssuers(const SECItem* encodedIssuerName,
                                           PRTime time,
                                   /*out*/ ScopedCERTCertList& results)
{
  results = CERT_CreateSubjectCertList(nullptr, CERT_GetDefaultCertDB(),
                                       encodedIssuerName, time, true);
  return SECSuccess;
}

struct WriteOCSPRequestDataClosure
{
  PLArenaPool* arena;
  SECItem* currentData;
};

size_t
WriteOCSPRequestData(void* ptr, size_t size, size_t nmemb, void* userdata)
{
  WriteOCSPRequestDataClosure* closure(
    reinterpret_cast<WriteOCSPRequestDataClosure*>(userdata));
  if (!closure || !closure->arena) {
    return 0;
  }

  if (!closure->currentData) {
    closure->currentData = SECITEM_AllocItem(closure->arena, nullptr,
                                             size * nmemb);
    if (!closure->currentData) {
      return 0;
    }

    memcpy(closure->currentData->data, ptr, size * nmemb);
    return size * nmemb;
  }

  SECItem* tmp = SECITEM_AllocItem(closure->arena, nullptr,
                                   closure->currentData->len + (size * nmemb));
  if (!tmp) {
    return 0;
  }
  memcpy(tmp->data, closure->currentData->data, closure->currentData->len);
  memcpy(tmp->data + closure->currentData->len, ptr, size * nmemb);
  SECITEM_FreeItem(closure->currentData, true);
  closure->currentData = tmp;
  return size * nmemb;
}

// Data returned is owned by arena.
SECItem*
MakeOCSPRequest(PLArenaPool* arena, const char* url, const SECItem* ocspRequest)
{
  if (!arena || !ocspRequest) {
    PR_SetError(SEC_ERROR_INVALID_ARGS, 0);
    return nullptr;
  }

  WriteOCSPRequestDataClosure closure({ arena, nullptr });
  CURL* curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, ocspRequest->data);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, ocspRequest->len);
  mozilla::pkix::ScopedPtr<struct curl_slist, curl_slist_free_all>
    contentType(curl_slist_append(nullptr,
                                  "Content-Type: application/ocsp-request"));
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, contentType.get());
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteOCSPRequestData);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &closure);
  CURLcode res = curl_easy_perform(curl);
  if (res != CURLE_OK) {
    if (closure.currentData) {
      SECITEM_FreeItem(closure.currentData, true);
    }
    PR_SetError(SEC_ERROR_OCSP_SERVER_ERROR, 0);
    return nullptr;
  }

  if (closure.currentData) {
    return closure.currentData;
  }
  PR_SetError(SEC_ERROR_OCSP_SERVER_ERROR, 0);
  return nullptr;
}

SECStatus
EVCheckerTrustDomain::CheckRevocation(EndEntityOrCA endEntityOrCA,
                                      const CERTCertificate* cert,
                            /*const*/ CERTCertificate* issuerCertToDup,
                                      PRTime time,
                         /*optional*/ const SECItem* stapledOCSPresponse)
{
  ScopedString aiaURL(CERT_GetOCSPAuthorityInfoAccessLocation(cert));
  if (!aiaURL) {
    PR_SetError(EV_CHECKER_NO_OCSP_AIA, 0);
    return SECFailure;
  }

  ScopedPLArenaPool arena(PORT_NewArena(DER_DEFAULT_CHUNKSIZE));
  if (!arena) {
    return SECFailure;
  }

  SECItem* ocspRequest = CreateEncodedOCSPRequest(arena.get(), cert,
                                                  issuerCertToDup);
  if (!ocspRequest) {
    return SECFailure;
  }

  SECItem* ocspResponse = MakeOCSPRequest(arena.get(), aiaURL.get(),
                                          ocspRequest);
  if (!ocspResponse) {
    return SECFailure;
  }

  return VerifyEncodedOCSPResponse(*this, cert, issuerCertToDup, time, 10,
                                   ocspResponse, nullptr, nullptr);
}

SECStatus
EVCheckerTrustDomain::IsChainValid(const CERTCertList* certChain)
{
  size_t chainLen = 0;
  for (CERTCertListNode* node = CERT_LIST_HEAD(certChain);
       !CERT_LIST_END(node, certChain);
       node = CERT_LIST_NEXT(node)) {
    chainLen++;
  }
  if (chainLen < 3) {
    PR_SetError(EV_CHECKER_DIRECTLY_ISSUED_CERT, 0);
    return SECFailure;
  }

  return SECSuccess;
}

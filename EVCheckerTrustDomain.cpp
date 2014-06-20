/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "EVCheckerTrustDomain.h"

#include "Util.h"
#include "prerror.h"
#include "secerr.h"

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

SECStatus
EVCheckerTrustDomain::CheckRevocation(EndEntityOrCA endEntityOrCA,
                                      const CERTCertificate* cert,
                            /*const*/ CERTCertificate* issuerCertToDup,
                                      PRTime time,
                         /*optional*/ const SECItem* stapledOCSPresponse)
{
  return SECSuccess;
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

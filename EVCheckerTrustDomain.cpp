/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "EVCheckerTrustDomain.h"

using namespace mozilla::pkix;

EVCheckerTrustDomain::EVCheckerTrustDomain(CERTCertificate* root)
 : mRoot(root)
{
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
  return SECSuccess;
}

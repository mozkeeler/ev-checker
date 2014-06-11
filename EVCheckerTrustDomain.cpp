/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "EVCheckerTrustDomain.h"

using namespace mozilla::pkix;

EVCheckerTrustDomain::EVCheckerTrustDomain()
{
}

SECStatus
EVCheckerTrustDomain::GetCertTrust(EndEntityOrCA endEntityOrCA,
                                   const CertPolicyId& policy,
                                   const SECItem& candidateCertDER,
                           /*out*/ TrustLevel* trustLevel)
{
  return SECSuccess;
}

SECStatus
EVCheckerTrustDomain::FindPotentialIssuers(const SECItem* encodedIssuerName,
                                           PRTime time,
                                   /*out*/ ScopedCERTCertList& results)
{
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

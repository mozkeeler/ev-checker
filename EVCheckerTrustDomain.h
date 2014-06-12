/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef EVCheckerTrustDomain_h
#define EVCheckerTrustDomain_h

#include "pkix/pkix.h"
#include "pkix/pkixtypes.h"

class EVCheckerTrustDomain : public mozilla::pkix::TrustDomain
{
public:
  explicit EVCheckerTrustDomain(CERTCertificate* root);

  SECStatus Init(const char* dottedEVPolicyOID, const char* evPolicyName);

  SECStatus GetFirstEVPolicyForCert(const CERTCertificate* cert,
                     /*out*/ mozilla::pkix::CertPolicyId& policy);

  virtual SECStatus GetCertTrust(mozilla::pkix::EndEntityOrCA endEntityOrCA,
                                 const mozilla::pkix::CertPolicyId& policy,
                                 const SECItem& candidateCertDER,
                         /*out*/ mozilla::pkix::TrustLevel* trustLevel);

  virtual SECStatus FindPotentialIssuers(
                      const SECItem* encodedIssuerName,
                      PRTime time,
              /*out*/ mozilla::pkix::ScopedCERTCertList& results);

  virtual SECStatus VerifySignedData(const CERTSignedData* signedData,
                                     const SECItem& subjectPublicKeyInfo)
  {
    return mozilla::pkix::VerifySignedData(signedData, subjectPublicKeyInfo,
                                           nullptr);
  }

  virtual SECStatus CheckRevocation(mozilla::pkix::EndEntityOrCA endEntityOrCA,
                                    const CERTCertificate* cert,
                          /*const*/ CERTCertificate* issuerCertToDup,
                                    PRTime time,
                       /*optional*/ const SECItem* stapledOCSPresponse);

  virtual SECStatus IsChainValid(const CERTCertList* certChain);

private:
  mozilla::pkix::ScopedCERTCertificate mRoot;
  SECOidTag mEVPolicyOIDTag;
};

#endif // EVCheckerTrustDomain_h

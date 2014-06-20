/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <iostream>

#include "Util.h"

#include "prerror.h"

void
PrintPRError(const char* message)
{
  const char* err = PR_ErrorToName(PR_GetError());
  if (err) {
    std::cerr << message << ": " << err << std::endl;
  } else {
    std::cerr << message << std::endl;
  }
}

void
PrintPRErrorString()
{
  std::cerr << PR_ErrorToString(PR_GetError(), 0) << std::endl;
}

static const struct PRErrorMessage EVCheckerErrorsTableText[] = {
  { "EV_CHECKER_DIRECTLY_ISSUED_CERT",
    "The root certificate directly issued the end-entity certificate. "
    "This is invalid under the baseline requirements for EV." }
};

static const struct PRErrorTable EVCheckerErrorsTable = {
  EVCheckerErrorsTableText,
  "ev-checker-errors",
  EV_CHECKER_ERRORS_BASE,
  PR_ARRAY_SIZE(EVCheckerErrorsTableText)
};

void
RegisterEVCheckerErrors()
{
  PR_ErrorInstallTable(&EVCheckerErrorsTable);
}

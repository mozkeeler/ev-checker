/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef Util_h
#define Util_h

void PrintPRError(const char* message);
void PrintPRErrorString();

const long EV_CHECKER_ERRORS_BASE = -(0x4000);

enum EVCheckerErrorCodes {
  EV_CHECKER_DIRECTLY_ISSUED_CERT = EV_CHECKER_ERRORS_BASE + 0
};

void RegisterEVCheckerErrors();

#endif // Util_h

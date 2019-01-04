// Copyright 2019 rel-eng
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package ru.releng.nwgss.sspi;

import com.sun.jna.platform.win32.WinError;

public final class SspiErrors {

    private SspiErrors() {
    }

    public static String decodeError(int errorCode) {
        switch (errorCode) {
            case WinError.SEC_E_INSUFFICIENT_MEMORY:
                return "Not enough memory is available to complete this request";
            case WinError.SEC_E_INVALID_HANDLE:
                return "The handle specified is invalid";
            case WinError.SEC_E_UNSUPPORTED_FUNCTION:
                return "The function requested is not supported";
            case WinError.SEC_E_TARGET_UNKNOWN:
                return "The specified target is unknown or unreachable";
            case WinError.SEC_E_INTERNAL_ERROR:
                return "The Local Security Authority cannot be contacted";
            case WinError.SEC_E_SECPKG_NOT_FOUND:
                return "The requested security package does not exist";
            case WinError.SEC_E_NOT_OWNER:
                return "The caller is not the owner of the desired credentials";
            case WinError.SEC_E_CANNOT_INSTALL:
                return "The security package failed to initialize, and cannot be installed";
            case WinError.SEC_E_INVALID_TOKEN:
                return "The token supplied to the function is invalid";
            case WinError.SEC_E_CANNOT_PACK:
                return "The security package is not able to marshall the logon buffer, so the logon attempt has failed";
            case WinError.SEC_E_QOP_NOT_SUPPORTED:
                return "The per-message Quality of Protection is not supported by the security package";
            case WinError.SEC_E_NO_IMPERSONATION:
                return "The security context does not allow impersonation of the client";
            case WinError.SEC_E_LOGON_DENIED:
                return "The logon attempt failed";
            case WinError.SEC_E_UNKNOWN_CREDENTIALS:
                return "The credentials supplied to the package were not recognized";
            case WinError.SEC_E_NO_CREDENTIALS:
                return "No credentials are available in the security package";
            case WinError.SEC_E_MESSAGE_ALTERED:
                return "The message or signature supplied for verification has been altered";
            case WinError.SEC_E_OUT_OF_SEQUENCE:
                return "The message supplied for verification is out of sequence";
            case WinError.SEC_E_NO_AUTHENTICATING_AUTHORITY:
                return "No authority could be contacted for authentication";
            default:
                return "Unexpected error code 0x" + Integer.toHexString(errorCode);
        }
    }

}

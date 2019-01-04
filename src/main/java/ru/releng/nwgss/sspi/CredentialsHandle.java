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

import com.sun.jna.platform.win32.Secur32;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.Sspi.CredHandle;
import com.sun.jna.platform.win32.WinError;

import javax.security.sasl.SaslException;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class CredentialsHandle {

    private static final Logger logger = Logger.getLogger(CredentialsHandle.class.getName());

    private final String principalName;
    private final int credentialsType;
    private final String securityPackage;

    private CredHandle handle;

    private CredentialsHandle(String principalName, int credentialsType, String securityPackage) {
        this.principalName = principalName;
        this.credentialsType = credentialsType;
        this.securityPackage = securityPackage;
    }

    public static CredentialsHandle currentPrincipal(String securityPackage) throws SaslException {
        CredentialsHandle credentialsHandle = new CredentialsHandle(null, Sspi.SECPKG_CRED_OUTBOUND, securityPackage);
        credentialsHandle.initialize();
        return credentialsHandle;
    }

    public void initialize() throws SaslException {
        logger.log(Level.FINEST, "Initializing credentials handle...");
        handle = new CredHandle();
        Sspi.TimeStamp clientLifetime = new Sspi.TimeStamp();
        int result = Secur32.INSTANCE.AcquireCredentialsHandle(principalName, securityPackage,
                credentialsType, null, null, null, null, handle, clientLifetime);
        if (result != WinError.SEC_E_OK) {
            throw new SaslException(SspiErrors.decodeError(result));
        }
        logger.log(Level.FINEST, "Credentials handle successfully initialized");
    }

    public void dispose() throws SaslException {
        if (handle == null || handle.isNull()) {
            return;
        }
        logger.log(Level.FINEST, "Disposing of credentials handle...");
        int result = Secur32.INSTANCE.FreeCredentialsHandle(handle);
        if (result != WinError.SEC_E_OK) {
            throw new SaslException(SspiErrors.decodeError(result));
        }
        logger.log(Level.FINEST, "Credentials handle was successfully disposed of");
    }

    public CredHandle getHandle() {
        return handle;
    }

}

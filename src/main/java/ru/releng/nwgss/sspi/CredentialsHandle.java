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

import com.sun.jna.Memory;
import com.sun.jna.platform.win32.Secur32;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.Sspi.CredHandle;
import com.sun.jna.platform.win32.WinError;

import javax.security.sasl.SaslException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
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

    public static CredentialsHandle selectedPrincipal(String securityPackage, String principalName, String login,
                                                      String domain, char[] password) throws SaslException
    {
        CredentialsHandle credentialsHandle = new CredentialsHandle(principalName, Sspi.SECPKG_CRED_OUTBOUND, securityPackage);
        credentialsHandle.initialize(login, domain, password);
        return credentialsHandle;
    }

    private void initialize() throws SaslException {
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

    private void initialize(String login, String domain, char[] password) throws SaslException {
        logger.log(Level.FINEST, "Initializing credentials handle...");
        handle = new CredHandle();
        Sspi.TimeStamp clientLifetime = new Sspi.TimeStamp();
        // Convert password to bytes
        byte[] passwordBytes = charsToBytesNullTerminated(password);
        Memory passwordMemory = null;
        int result;
        try {
            // Copy password bytes to native memory
            try {
                passwordMemory = new Memory(passwordBytes.length);
                passwordMemory.write(0, passwordBytes, 0, passwordBytes.length);
            } finally {
                // Clear source password bytes
                Arrays.fill(passwordBytes, (byte) 0);
            }
            int passwordLengthWithoutNull = passwordBytes.length - 2;
            SspiExt.SEC_WINNT_AUTH_IDENTITY identity = new SspiExt.SEC_WINNT_AUTH_IDENTITY();
            identity.User = login;
            identity.Domain = domain;
            identity.Password = passwordMemory;
            identity.PasswordLength = passwordLengthWithoutNull;
            identity.write();
            result = Secur32.INSTANCE.AcquireCredentialsHandle(principalName, securityPackage,
                    credentialsType, null, identity.getPointer(), null, null, handle, clientLifetime);
        } finally {
            // Clear password from native memory
            if (passwordMemory != null) {
                passwordMemory.clear();
            }
        }
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

    private byte[] charsToBytesNullTerminated(char[] chars) {
        CharBuffer charBuffer = CharBuffer.wrap(chars);
        ByteBuffer byteBuffer = encode(StandardCharsets.UTF_16LE, charBuffer);
        ByteBuffer nullTerminatedByteBuffer = null;
        byte[] bytes;
        try {
            try {
                nullTerminatedByteBuffer = ByteBuffer.allocate(byteBuffer.limit() + 2);
                nullTerminatedByteBuffer.put(byteBuffer);
                // Add null terminator symbol, two bytes
                nullTerminatedByteBuffer.put((byte) 0);
                nullTerminatedByteBuffer.put((byte) 0);
                nullTerminatedByteBuffer.flip();
            } finally {
                // Clear the source buffer
                Arrays.fill(byteBuffer.array(), (byte) 0);
            }
            bytes = Arrays.copyOfRange(nullTerminatedByteBuffer.array(), nullTerminatedByteBuffer.position(),
                    nullTerminatedByteBuffer.limit());
        } finally {
            // Clear byte buffer when it is not needed anymore
            if (nullTerminatedByteBuffer != null) {
                Arrays.fill(nullTerminatedByteBuffer.array(), (byte) 0);
            }
        }
        return bytes;
    }

    private ByteBuffer encode(Charset charset, CharBuffer charBuffer) {
        CharsetEncoder encoder = charset.newEncoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE);
        int outputByteBufferCapacity = (int) (charBuffer.remaining() * encoder.averageBytesPerChar());
        ByteBuffer outputByteBuffer = ByteBuffer.allocate(outputByteBufferCapacity);
        if ((outputByteBufferCapacity == 0) && (charBuffer.remaining() == 0)) {
            return outputByteBuffer;
        }
        encoder.reset();
        boolean success = false;
        try {
            while (true) {
                CoderResult coderResult = charBuffer.hasRemaining()
                        ? encoder.encode(charBuffer, outputByteBuffer, true)
                        : CoderResult.UNDERFLOW;
                if (coderResult.isUnderflow()) {
                    coderResult = encoder.flush(outputByteBuffer);
                }
                if (coderResult.isUnderflow()) {
                    break;
                }
                if (coderResult.isOverflow()) {
                    outputByteBufferCapacity = 2 * outputByteBufferCapacity + 1;
                    ByteBuffer expandedOutputByteBuffer = ByteBuffer.allocate(outputByteBufferCapacity);
                    outputByteBuffer.flip();
                    expandedOutputByteBuffer.put(outputByteBuffer);
                    ByteBuffer oldByteBuffer = outputByteBuffer;
                    outputByteBuffer = expandedOutputByteBuffer;
                    // Clear all intermediate buffers which might contain parts of a password
                    Arrays.fill(oldByteBuffer.array(), (byte) 0);
                    continue;
                }
                try {
                    coderResult.throwException();
                } catch (CharacterCodingException e) {
                    outputByteBuffer.clear();
                    throw new RuntimeException(e);
                }
            }
            outputByteBuffer.flip();
            success = true;
            return outputByteBuffer;
        } finally {
            if (!success) {
                // Clear password output buffer on failure
                outputByteBuffer.clear();
            }
        }
    }

}

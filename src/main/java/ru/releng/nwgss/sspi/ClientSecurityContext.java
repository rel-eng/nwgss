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
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Secur32;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.SspiUtil;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.ptr.IntByReference;

import javax.security.sasl.SaslException;

public class ClientSecurityContext {

    private static final int SECBUFFER_PADDING = 9;
    private static final int SECBUFFER_STREAM = 10;
    private static final int SEC_WRAP_NO_ENCRYPT = 0x80000001;

    private final CredentialsHandle credentialsHandle;
    private final SecurityContextRequirements requirements;

    private boolean continueFlag = false;
    private Sspi.CtxtHandle contextHandle = null;
    private int blockSize = 0;
    private int maxToken = 0;

    public ClientSecurityContext(CredentialsHandle credentialsHandle, SecurityContextRequirements requirements) {
        this.credentialsHandle = credentialsHandle;
        this.requirements = requirements;
    }

    public byte[] initialize(byte[] challenge, String targetName) throws SaslException {
        SspiUtil.ManagedSecBufferDesc continueToken;
        if (challenge == null || challenge.length == 0) {
            continueToken = null;
        } else {
            continueToken = new SspiUtil.ManagedSecBufferDesc(Sspi.SECBUFFER_TOKEN, challenge);
        }
        IntByReference contextAttributes = new IntByReference();
        Sspi.CtxtHandle continueContextHandle = contextHandle;
        Sspi.CtxtHandle outputContextHandle = new Sspi.CtxtHandle();
        SspiUtil.ManagedSecBufferDesc token;
        int tokenSize = Sspi.MAX_TOKEN_SIZE;
        int result;
        do {
            token = new SspiUtil.ManagedSecBufferDesc(Sspi.SECBUFFER_TOKEN, tokenSize);
            result = Secur32.INSTANCE.InitializeSecurityContext(credentialsHandle.getHandle(), continueContextHandle,
                    targetName, prepareRequirements(), 0, Sspi.SECURITY_NATIVE_DREP, continueToken, 0,
                    outputContextHandle, token, contextAttributes, null);
            switch (result) {
                case WinError.SEC_E_INSUFFICIENT_MEMORY:
                case WinError.SEC_E_BUFFER_TOO_SMALL:
                    tokenSize += Sspi.MAX_TOKEN_SIZE;
                    break;
                case WinError.SEC_I_CONTINUE_NEEDED:
                    continueFlag = true;
                    break;
                case WinError.SEC_E_OK:
                    continueFlag = false;
                    break;
                default:
                    throw new SaslException(SspiErrors.decodeError(result));
            }
        } while (result == WinError.SEC_E_INSUFFICIENT_MEMORY || result == WinError.SEC_E_BUFFER_TOO_SMALL);
        contextHandle = outputContextHandle;
        if (!continueFlag) {
            validateRequirements(contextAttributes.getValue());
            queryContextSizes();
        }
        if (token.getBuffer(0).getBytes() == null) {
            return new byte[0];
        }
        return token.getBuffer(0).getBytes();
    }

    public void dispose() throws SaslException {
        if (contextHandle == null || contextHandle.isNull()) {
            return;
        }
        int result = Secur32.INSTANCE.DeleteSecurityContext(contextHandle);
        if (result != WinError.SEC_E_OK) {
            throw new SaslException(SspiErrors.decodeError(result));
        }
    }

    public byte[] wrap(byte[] outgoing, int offset, int len, boolean noEncrypt) throws SaslException {
        SspiUtil.ManagedSecBufferDesc wrapBuffers = new SspiUtil.ManagedSecBufferDesc(3);
        Memory tokenMemory = new Memory(maxToken);
        Memory dataMemory = new Memory(len);
        Memory paddingMemory = new Memory(blockSize);
        dataMemory.write(0, outgoing, offset, len);
        wrapBuffers.getBuffer(0).BufferType = Sspi.SECBUFFER_TOKEN;
        wrapBuffers.getBuffer(0).cbBuffer = (int) tokenMemory.size();
        wrapBuffers.getBuffer(0).pvBuffer = tokenMemory;
        wrapBuffers.getBuffer(1).BufferType = Sspi.SECBUFFER_DATA;
        wrapBuffers.getBuffer(1).cbBuffer = (int) dataMemory.size();
        wrapBuffers.getBuffer(1).pvBuffer = dataMemory;
        wrapBuffers.getBuffer(2).BufferType = SECBUFFER_PADDING;
        wrapBuffers.getBuffer(2).cbBuffer = (int) paddingMemory.size();
        wrapBuffers.getBuffer(2).pvBuffer = paddingMemory;
        int wrapResult = Secur32.INSTANCE.EncryptMessage(contextHandle,
                noEncrypt ? SEC_WRAP_NO_ENCRYPT : 0, wrapBuffers, 0);
        if (wrapResult != WinError.SEC_E_OK) {
            throw new SaslException(SspiErrors.decodeError(wrapResult));
        }
        byte[] trailer = wrapBuffers.getBuffer(0).getBytes();
        byte[] data = wrapBuffers.getBuffer(1).getBytes();
        byte[] padding = wrapBuffers.getBuffer(2).getBytes();
        byte[] result = new byte[trailer.length + data.length + padding.length];
        if (trailer.length > 0) {
            System.arraycopy(trailer, 0, result, 0, trailer.length);
        }
        if (data.length > 0) {
            System.arraycopy(data, 0, result, trailer.length, data.length);
        }
        if (padding.length > 0) {
            System.arraycopy(padding, 0, result, trailer.length + data.length, padding.length);
        }
        return result;
    }

    public byte[] unwrap(byte[] incoming, int offset, int len, boolean noEncryptAllowed) throws SaslException {
        SspiUtil.ManagedSecBufferDesc unwrapBuffers = new SspiUtil.ManagedSecBufferDesc(2);
        Memory dataMemory = new Memory(len);
        dataMemory.write(0, incoming, offset, len);
        unwrapBuffers.getBuffer(0).BufferType = SECBUFFER_STREAM;
        unwrapBuffers.getBuffer(0).cbBuffer = (int) dataMemory.size();
        unwrapBuffers.getBuffer(0).pvBuffer = dataMemory;
        unwrapBuffers.getBuffer(1).BufferType = Sspi.SECBUFFER_DATA;
        unwrapBuffers.getBuffer(1).cbBuffer = 0;
        unwrapBuffers.getBuffer(1).pvBuffer = Pointer.NULL;
        IntByReference qopResult = new IntByReference();
        int unwrapResult = Secur32.INSTANCE.DecryptMessage(contextHandle, unwrapBuffers, 0, qopResult);
        if (unwrapResult != WinError.SEC_E_OK) {
            throw new SaslException(SspiErrors.decodeError(unwrapResult));
        }
        if (qopResult.getValue() == SEC_WRAP_NO_ENCRYPT && !noEncryptAllowed) {
            throw new SaslException("Confidentiality requirement is not satisfied");
        }
        return unwrapBuffers.getBuffer(1).getBytes();
    }

    public boolean isContinue() {
        return continueFlag;
    }

    private int prepareRequirements() {
        int result = Sspi.ISC_REQ_CONNECTION;
        if (requirements.isConfidentiality()) {
            result |= Sspi.ISC_REQ_CONFIDENTIALITY;
        }
        if (requirements.isIntegrity()) {
            result |= Sspi.ISC_REQ_INTEGRITY;
        }
        if (requirements.isMutualAuthentication()) {
            result |= Sspi.ISC_REQ_MUTUAL_AUTH;
        }
        if (requirements.isReplayDetect()) {
            result |= Sspi.ISC_REQ_REPLAY_DETECT;
        }
        if (requirements.isSequenceDetect()) {
            result |= Sspi.ISC_REQ_SEQUENCE_DETECT;
        }
        if (requirements.isDelegation()) {
            result |= Sspi.ISC_REQ_DELEGATE;
        }
        return result;
    }

    private void validateRequirements(int contextAttributes) throws SaslException {
        if (requirements.isConfidentiality() && ((contextAttributes & Sspi.ISC_REQ_CONFIDENTIALITY) == 0)) {
            throw new SaslException("Confidentiality requirement is not satisfied");
        }
        if (requirements.isIntegrity() && ((contextAttributes & Sspi.ISC_REQ_INTEGRITY) == 0)) {
            throw new SaslException("Integrity requirement is not satisfied");
        }
        if (requirements.isMutualAuthentication() && ((contextAttributes & Sspi.ISC_REQ_MUTUAL_AUTH) == 0)) {
            throw new SaslException("Mutual authentication requirement is not satisfied");
        }
        if (requirements.isReplayDetect() && ((contextAttributes & Sspi.ISC_REQ_REPLAY_DETECT) == 0)) {
            throw new SaslException("Replay detection requirement is not satisfied");
        }
        if (requirements.isSequenceDetect() && ((contextAttributes & Sspi.ISC_REQ_SEQUENCE_DETECT) == 0)) {
            throw new SaslException("Out-of-sequence detection requirement is not satisfied");
        }
        if (requirements.isDelegation() && ((contextAttributes & Sspi.ISC_REQ_DELEGATE) == 0)) {
            throw new SaslException("Delegation requirement is not satisfied");
        }
    }

    private void queryContextSizes() throws SaslException {
        Sspi.SecPkgContext_Sizes sizes = new Sspi.SecPkgContext_Sizes();
        int queryResult = Secur32.INSTANCE.QueryContextAttributes(contextHandle, Sspi.SECPKG_ATTR_SIZES, sizes);
        if (queryResult != WinError.SEC_E_OK) {
            throw new SaslException(SspiErrors.decodeError(queryResult));
        }
        blockSize = sizes.cbBlockSize;
        maxToken = sizes.cbMaxToken;
    }

}

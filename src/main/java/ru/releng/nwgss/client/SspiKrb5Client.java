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
package ru.releng.nwgss.client;

import ru.releng.nwgss.sspi.Account;
import ru.releng.nwgss.sspi.ClientSecurityContext;
import ru.releng.nwgss.sspi.CredentialsHandle;
import ru.releng.nwgss.sspi.SecurityContextRequirements;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.io.IOException;
import java.lang.ref.Cleaner;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SspiKrb5Client implements SaslClient {

    private static final Logger logger = Logger.getLogger(SspiKrb5Client.class.getName());

    // Cleaner for native resources
    private static final Cleaner CLEANER = Cleaner.create();

    private static final String SEND_MAX_BUFFER = "javax.security.sasl.sendmaxbuffer";
    private static final String SECURITY_PACKAGE = "Kerberos";

    private static final byte NO_PROTECTION = (byte) 1;
    private static final byte INTEGRITY_ONLY_PROTECTION = (byte) 2;
    private static final byte PRIVACY_PROTECTION = (byte) 4;
    private static final byte[] DEFAULT_QOP = {PRIVACY_PROTECTION};
    private static final List<TokenByte> QOP_SETTINGS = List.of(new TokenByte("auth-conf", PRIVACY_PROTECTION),
            new TokenByte("auth-int", INTEGRITY_ONLY_PROTECTION), new TokenByte("auth", NO_PROTECTION));

    private final String servicePrincipalName;
    private final SecurityContextRequirements contextRequirements;
    private final DisposableResources disposableResources;
    private final Cleaner.Cleanable cleanable;

    // Set after connection is fully established
    private boolean authenticationComplete = false;
    // Is confidentiality protection negotiated
    private boolean confidentialityProtected = false;
    // Is integrity protection negotiated
    private boolean integrityProtected = false;
    // Set after client context is initialized, need to do final handshake at this moment
    private boolean finalHandshake = false;
    // Is mutual client and server authentication required, set as parameter
    private boolean mutualAuthenticationRequired = false;
    // Maximum send buffer size is received from server but can also be set less than that
    private int sendMaxBufferSize = 0;
    private int receiveMaxBufferSize = 65536;
    // At most this number of bytes can be wrapped, that the result won't exceed the server receive buffer size
    private int rawSendSize = 0;
    private byte[] authorizationId;
    private byte[] clientQopPreference;
    private byte clientQopPreferenceMask;

    public SspiKrb5Client(String authorizationId, String protocol, String serverName, Map<String, ?> props,
                          CallbackHandler cbh) throws SaslException
    {
        this.servicePrincipalName = protocol + "/" + serverName;
        logger.log(Level.FINEST, "Requesting SPN: {0}", servicePrincipalName);
        if (props != null) {
            parseProperties(props);
        } else {
            clientQopPreference = DEFAULT_QOP;
            clientQopPreferenceMask = NO_PROTECTION;
        }
        if (authorizationId != null && authorizationId.length() > 0) {
            logger.log(Level.FINEST, "Authorization id: {0}", authorizationId);
            this.authorizationId = authorizationId.getBytes(StandardCharsets.UTF_8);
        }
        boolean confidentialityRequired = (clientQopPreferenceMask & PRIVACY_PROTECTION) != 0;
        boolean integrityRequired = (clientQopPreferenceMask & PRIVACY_PROTECTION) != 0
                || (clientQopPreferenceMask & INTEGRITY_ONLY_PROTECTION) != 0;
        SecurityContextRequirements requirements = SecurityContextRequirements.builder()
                .setConfidentiality(confidentialityRequired)
                .setIntegrity(integrityRequired)
                .setMutualAuthentication(mutualAuthenticationRequired)
                .setReplayDetect(true)
                .setSequenceDetect(true)
                .build();
        this.contextRequirements = requirements;
        CredentialsHandle clientCredentials = prepareCredentials(cbh);
        // Must properly dispose of clientCredentials if constructor fails after this point
        ClientSecurityContext securityContext = new ClientSecurityContext(clientCredentials, requirements);
        this.disposableResources = new DisposableResources(clientCredentials, securityContext);
        this.cleanable = CLEANER.register(this, disposableResources);
    }

    @Override
    public String getMechanismName() {
        return "GSSAPI";
    }

    @Override
    public boolean hasInitialResponse() {
        return true;
    }

    @Override
    public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
        if (authenticationComplete) {
            throw new IllegalStateException("SASL authentication had already been completed");
        }
        if (finalHandshake) {
            logger.log(Level.FINEST, "Doing final handshake...");
            byte[] result = doFinalHandshake(challenge);
            logger.log(Level.FINEST, "Final handshake done");
            return result;
        }
        logger.log(Level.FINEST, "Evaluating challenge...");
        ClientSecurityContext securityContext = disposableResources.getSecurityContext();
        byte[] outgoingToken = securityContext.initialize(challenge, servicePrincipalName);
        logger.log(Level.FINEST, "Challenge evaluated");
        finalHandshake = !securityContext.isContinue();
        return outgoingToken;
    }

    @Override
    public boolean isComplete() {
        return authenticationComplete;
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
        if (!authenticationComplete) {
            throw new IllegalStateException("SASL authentication had not been completed");
        }
        ClientSecurityContext securityContext = disposableResources.getSecurityContext();
        return securityContext.unwrap(incoming, offset, len, !contextRequirements.isConfidentiality());
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
        if (!authenticationComplete) {
            throw new IllegalStateException("SASL authentication had not been completed");
        }
        ClientSecurityContext securityContext = disposableResources.getSecurityContext();
        return securityContext.wrap(outgoing, offset, len, !contextRequirements.isConfidentiality());
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
        if (!authenticationComplete) {
            throw new IllegalStateException("SASL authentication had not been completed");
        }
        switch (propName) {
            case Sasl.MAX_BUFFER:
                return Integer.toString(receiveMaxBufferSize);
            case SEND_MAX_BUFFER:
                return Integer.toString(sendMaxBufferSize);
            case Sasl.RAW_SEND_SIZE:
                return Integer.toString(rawSendSize);
            case Sasl.QOP:
                if (confidentialityProtected) {
                    return "auth-conf";
                } else if (integrityProtected) {
                    return "auth-int";
                } else {
                    return "auth";
                }
            default:
                return null;
        }
    }

    @Override
    public void dispose() throws SaslException {
        cleanable.clean();
    }

    private CredentialsHandle prepareCredentials(CallbackHandler cbh) throws SaslException {
        // Callbacks to retrieve user credentials
        RealmCallback domainCallback = new RealmCallback("Domain: ");
        NameCallback nameCallback = new NameCallback("Name: ");
        PasswordCallback passwordCallback = new PasswordCallback("Password: ", false);
        boolean callbackSuccess = false;
        try {
            cbh.handle(new Callback[] { domainCallback, nameCallback, passwordCallback });
            callbackSuccess = true;
        } catch (UnsupportedCallbackException e) {
            throw new SaslException("Unsupported authorization callback", e);
        } catch (IOException e) {
            throw new SaslException("Authorization callback error", e);
        } finally {
            if (!callbackSuccess) {
                // Clear the password on failure
                passwordCallback.clearPassword();
            }
        }
        String domain = domainCallback.getText();
        String login = nameCallback.getName();
        char[] password = passwordCallback.getPassword();
        try {
            if (domain == null || domain.isEmpty() || login == null || login.isEmpty()
                    || password == null || password.length == 0)
            {
                // Not enough credentials, use current user account
                if (logger.isLoggable(Level.FINEST)) {
                    String targetName = Account.getCurrentUserNameSamCompatible();
                    logger.log(Level.FINEST, "Using credentials for {0}", targetName);
                }
                return CredentialsHandle.currentPrincipal(SECURITY_PACKAGE);
            } else {
                // Use supplied credentials
                logger.log(Level.FINEST, "Using credentials for {0}\\{1}", new Object[] {domain, login});
                return CredentialsHandle.selectedPrincipal(SECURITY_PACKAGE, domain + '\\' + login, login, domain, password);
            }
        } finally {
            // Clear the password when it is no longer needed
            if (password != null) {
                Arrays.fill(password, ' ');
            }
            passwordCallback.clearPassword();
        }
    }

    private byte[] doFinalHandshake(byte[] challenge) throws SaslException {
        // RFC4752 stuff
        if (challenge == null || challenge.length == 0) {
            return new byte[0];
        }
        ClientSecurityContext securityContext = disposableResources.getSecurityContext();
        // Expect to receive data with integrity protection only
        byte[] unwrappedChallenge = securityContext.unwrap(challenge, 0, challenge.length, true);
        if (unwrappedChallenge.length < 4) {
            // If the resulting cleartext is not 4 octets long, the client fails the negotiation
            throw new SaslException("Server response during the final handshake is too short");
        }
        // First unwrapped octet is a bit-mask specifying the security layers supported by the server
        byte serverSupportedSecurityLayers = unwrappedChallenge[0];
        byte selectedQop = findPreferredQop(serverSupportedSecurityLayers, clientQopPreference);
        if (selectedQop == 0) {
            throw new SaslException("Unable to negotiate common quality-of-protection between client and server");
        }
        if ((selectedQop & PRIVACY_PROTECTION) != 0) {
            confidentialityProtected = true;
            integrityProtected = true;
        } else if ((selectedQop & INTEGRITY_ONLY_PROTECTION) != 0) {
            integrityProtected = true;
        }
        // Second through fourth octets are the maximum size output message the server is able to receive
        // (in network byte order)
        int serverMaxBufferSize = ntohi(unwrappedChallenge, 1, 3);
        sendMaxBufferSize = (sendMaxBufferSize == 0) ? serverMaxBufferSize : Math.min(sendMaxBufferSize, serverMaxBufferSize);
        // Using some conservative estimation
        // It should be more like gss_wrap_size_limit, but looks like it's counterpart is not present in SSPI,
        // It seems that SECPKG_ATTR_STREAM_SIZES is unavailable also, so cbMaximumMessage is unknown
        rawSendSize = serverMaxBufferSize > 200 ? serverMaxBufferSize - 200 : serverMaxBufferSize;
        int responseLength = 4;
        if (authorizationId != null) {
            responseLength += authorizationId.length;
        }
        byte[] response = new byte[responseLength];
        // First octet of the response contains the bit-mask specifying the selected security layer
        response[0] = selectedQop;
        // The second through fourth octets of the response contains in network byte order the maximum size output
        // message the client is able to receive
        htoni(receiveMaxBufferSize, response, 1, 3);
        if (authorizationId != null && authorizationId.length > 0) {
            System.arraycopy(authorizationId, 0, response, 4, authorizationId.length);
        }
        // Send with integrity protection only
        byte[] result = securityContext.wrap(response, 0, response.length, true);
        authenticationComplete = true;
        return result;
    }

    private byte findPreferredQop(byte supportedMask, byte[] preferred) {
        for (byte in : preferred) {
            if ((in & supportedMask) != 0) {
                return in;
            }
        }
        return (byte) 0;
    }

    private int ntohi(byte[] input, int offset, int length) {
        if (length > 4) {
            throw new IllegalArgumentException("Can not convert more than 4 bytes to integer");
        }
        int result = 0;
        for (int i = 0; i < length; i++) {
            result <<= 8;
            result |= ((int) input[offset + i] & 0xff);
        }
        return result;
    }

    private void htoni(int value, byte[] output, int offset, int length) {
        if (length > 4) {
            throw new IllegalArgumentException("Can not convert more than 4 bytes to integer");
        }
        int currentValue = value;
        for (int i = offset - 1; i >- 0; i--) {
            output[offset + i] = (byte) (currentValue & 0xff);
            currentValue >>>= 8;
        }
    }

    private void parseProperties(Map<String, ?> properties) throws SaslException {
        String qopProperty = (String) properties.get(Sasl.QOP);
        clientQopPreference = qopToBytes(qopProperty);
        logger.log(Level.FINEST, "Preferred quality-of-protection property: {0}", qopProperty);
        clientQopPreferenceMask = orBytes(clientQopPreference);
        logger.log(Level.FINEST, "Preferred quality-of-protection mask: {0}", clientQopPreferenceMask);
        if (clientQopPreference.length > 0 && logger.isLoggable(Level.FINEST)) {
            logger.log(Level.FINEST, "Preferred quality-of-protection masks : {0}", bytesAsString(clientQopPreference));
        }
        String maxBufferProperty = (String) properties.get(Sasl.MAX_BUFFER);
        if (maxBufferProperty != null) {
            logger.log(Level.FINEST, "Maximum receive buffer size: {0}", maxBufferProperty);
            try {
                receiveMaxBufferSize = Integer.parseInt(maxBufferProperty);
            } catch (NumberFormatException e) {
                throw new SaslException("The " + Sasl.MAX_BUFFER + " property must be a string representation of an integer");
            }
        }
        String sendMaxBufferProperty = (String) properties.get(SEND_MAX_BUFFER);
        if (sendMaxBufferProperty != null) {
            logger.log(Level.FINEST, "Maximum send buffer size: {0}", sendMaxBufferProperty);
            try {
                sendMaxBufferSize = Integer.parseInt(sendMaxBufferProperty);
            } catch (NumberFormatException e) {
                throw new SaslException("The " + SEND_MAX_BUFFER + " property must be a string representation of an integer");
            }
        }
        String mutualAuthenticationRequiredProperty = (String) properties.get(Sasl.SERVER_AUTH);
        if (mutualAuthenticationRequiredProperty != null) {
            logger.log(Level.FINEST, "Mutual authentication: {0}", mutualAuthenticationRequiredProperty);
            mutualAuthenticationRequired = Boolean.parseBoolean(mutualAuthenticationRequiredProperty);
        }
    }

    private static String bytesAsString(byte[] bytes) {
        List<String> values = new ArrayList<>(bytes.length);
        for (byte value : bytes) {
            values.add(Byte.toString(value));
        }
        return String.join(" ", values);
    }

    private static byte orBytes(byte[] in) {
        byte answer = 0;
        for (byte b : in) {
            answer |= b;
        }
        return answer;
    }

    private static byte[] qopToBytes(String qop) throws SaslException {
        if (qop == null) {
            return DEFAULT_QOP;
        }
        return propertyToBytes(Sasl.QOP, qop, QOP_SETTINGS);
    }

    private static byte[] propertyToBytes(String name, String value, List<TokenByte> mappings) throws SaslException {
        byte[] result = new byte[mappings.size()];
        Set<String> valueTokens = new LinkedHashSet<>(List.of(value.split("[, \t\n]")));
        int resultIndex = 0;
        for (String token : valueTokens) {
            if (resultIndex >= result.length) {
                break;
            }
            boolean found = false;
            for (TokenByte mapping : mappings) {
                if (mapping.getToken().equalsIgnoreCase(token)) {
                    result[resultIndex] = mapping.getValue();
                    resultIndex++;
                    found = true;
                    break;
                }
            }
            if (!found) {
                throw new SaslException("Unsupported value in " + name + ": " + value);
            }
        }
        for (int i = resultIndex; i < result.length; i++) {
            result[i] = 0;
        }
        return result;
    }

    private static final class DisposableResources implements Runnable {

        private final CredentialsHandle clientCredentials;
        private final ClientSecurityContext securityContext;

        private DisposableResources(CredentialsHandle clientCredentials, ClientSecurityContext securityContext) {
            this.clientCredentials = clientCredentials;
            this.securityContext = securityContext;
        }

        public CredentialsHandle getClientCredentials() {
            return clientCredentials;
        }

        public ClientSecurityContext getSecurityContext() {
            return securityContext;
        }

        @Override
        public void run() {
            Exception contextDisposalException = null;
            try {
                securityContext.dispose();
            } catch (Exception e) {
                contextDisposalException = e;
            }
            Exception credentialsDisposalException = null;
            try {
                clientCredentials.dispose();
            } catch (Exception e) {
                credentialsDisposalException = e;
            }
            if (contextDisposalException != null && credentialsDisposalException != null) {
                logger.log(Level.WARNING, "Failed to dispose of client credentials", credentialsDisposalException);
            }
            if (contextDisposalException != null) {
                throw new RuntimeException("Failed to dispose of security context", contextDisposalException);
            }
            if (credentialsDisposalException != null) {
                throw new RuntimeException("Failed to dispose of client credentials", credentialsDisposalException);
            }
        }

    }

    private static final class TokenByte {

        private final String token;
        private final byte value;

        private TokenByte(String token, byte value) {
            this.token = token;
            this.value = value;
        }

        String getToken() {
            return token;
        }

        byte getValue() {
            return value;
        }

    }

}

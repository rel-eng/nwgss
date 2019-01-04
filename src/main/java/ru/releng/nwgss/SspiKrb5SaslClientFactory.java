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
package ru.releng.nwgss;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import java.util.Map;

public final class SspiKrb5SaslClientFactory implements SaslClientFactory {

    private static final String MECHANISM = "GSSAPI";

    @Override
    public SaslClient createSaslClient(String[] mechanisms, String authorizationId, String protocol, String serverName,
                                       Map<String, ?> props, CallbackHandler cbh) throws SaslException
    {
        for (String mechanism : mechanisms) {
            if (MECHANISM.equals(mechanism) && getMechanismNames(props).length > 0) {
                return new SspiKrb5Client(authorizationId, protocol, serverName, props, cbh);
            }
        }
        return null;
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> props) {
        if (props == null || (!Boolean.valueOf((String) props.get(Sasl.POLICY_NODICTIONARY))
                && !Boolean.valueOf((String) props.get(Sasl.POLICY_FORWARD_SECRECY))
                && !Boolean.valueOf((String) props.get(Sasl.POLICY_PASS_CREDENTIALS))))
        {
            return new String[] { MECHANISM };
        }
        return new String[0];
    }

}

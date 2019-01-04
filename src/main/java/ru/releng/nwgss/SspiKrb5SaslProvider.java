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

import ru.releng.nwgss.client.SspiKrb5SaslClientFactory;

import java.security.AccessController;
import java.security.InvalidParameterException;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.ProviderException;

public final class SspiKrb5SaslProvider extends Provider {

    private static final String TYPE = "SaslClientFactory";
    private static final String ALGORITHM = "GSSAPI";

    public SspiKrb5SaslProvider() {
        super("SspiKrb5SaslProvider", "1.0", "SSPI Kerberos 5 SASL provider 1.0");
        final Provider provider = this;
        AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            putService(new ProviderService(provider, TYPE, ALGORITHM, SspiKrb5SaslClientFactory.class.getName()));
            return null;
        });
    }

    private static final class ProviderService extends Provider.Service {

        private ProviderService(Provider provider, String type, String algorithm, String className) {
            super(provider, type, algorithm, className, null, null);
        }

        @Override
        public Object newInstance(Object constructorParameter) {
            String type = getType();
            if (constructorParameter != null) {
                throw new InvalidParameterException("constructorParameter must be null for " + type + " engines");
            }
            String algorithm = getAlgorithm();
            if (algorithm.equals(ALGORITHM)) {
                return new SspiKrb5SaslClientFactory();
            }
            throw new ProviderException("No implementation for " + algorithm + " " + type);
        }
    }

}

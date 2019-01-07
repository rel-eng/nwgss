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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.RealmCallback;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Properties;

@RunWith(JUnit4.class)
public class ClientTest {

    @Test
    public void test() {
        Provider provider = new SspiKrb5SaslProvider();
        Security.insertProviderAt(provider, 1);

        LdapContext ldapContext;
        try {
            ldapContext = new InitialLdapContext(getGSSAPIProperties(), null);
        } catch (NamingException ex) {
            throw new RuntimeException(ex);
        }
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchControls.setReturningAttributes(new String[] {"cn", "sn", "userPrincipalName", "memberOf", "name"});
        try {
            for (int i = 0; i < 10; i++) {
                NamingEnumeration<SearchResult> result = ldapContext.search("CN=Users,DC=CONTOSO,DC=COM",
                        "(objectclass=organizationalPerson)", searchControls);
                try {
                    while (result.hasMore()) {
                        SearchResult oneResult = result.next();
                        System.out.println("Result: " + oneResult);
                    }
                } finally {
                    result.close();
                }
            }
        } catch (NamingException e) {
            throw new RuntimeException(e);
        }
        try {
            ldapContext.close();
        } catch (NamingException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testCredentials() {
        Provider provider = new SspiKrb5SaslProvider();
        Security.insertProviderAt(provider, 1);

        LdapContext ldapContext;
        try {
            ldapContext = new InitialLdapContext(getGSSAPIPropertiesWithCallback(), null);
        } catch (NamingException ex) {
            throw new RuntimeException(ex);
        }
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchControls.setReturningAttributes(new String[] {"cn", "sn", "userPrincipalName", "memberOf", "name"});
        try {
            for (int i = 0; i < 10; i++) {
                NamingEnumeration<SearchResult> result = ldapContext.search("CN=Users,DC=CONTOSO,DC=COM",
                        "(objectclass=organizationalPerson)", searchControls);
                try {
                    while (result.hasMore()) {
                        SearchResult oneResult = result.next();
                        System.out.println("Result: " + oneResult);
                    }
                } finally {
                    result.close();
                }
            }
        } catch (NamingException e) {
            throw new RuntimeException(e);
        }
        try {
            ldapContext.close();
        } catch (NamingException e) {
            throw new RuntimeException(e);
        }
    }

    private static Properties getGSSAPIPropertiesWithCallback() {
        Properties result = new Properties();
        result.put("java.naming.security.sasl.callback", new CustomCallbackHandler());
        result.putAll(getGSSAPIProperties());
        return result;
    }

    private static Properties getGSSAPIProperties() {
        Properties result = new Properties();
        result.put("javax.security.sasl.qop", "auth-conf");
        result.put("javax.security.sasl.server.authentication", "true");
        result.putAll(getLdapSettings());
        return result;
    }

    private static Properties getLdapSettings() {
        Properties result = new Properties();
        result.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");
        result.put("java.naming.referral", "ignore");
        result.put("java.naming.provider.url", "ldap://" + getLocalHostName() + ":389");
        result.put("java.naming.security.authentication", "GSSAPI");
        return result;
    }

    private static String getLocalHostName() {
        try {
            return InetAddress.getLocalHost().getCanonicalHostName();
        } catch (UnknownHostException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static class CustomCallbackHandler implements CallbackHandler {

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof RealmCallback) {
                    ((RealmCallback) callback).setText("CONTOSO");
                } else if (callback instanceof NameCallback) {
                    ((NameCallback) callback).setName("Administrator");
                } else if (callback instanceof PasswordCallback) {
                    char[] password = new char[] {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
                    ((PasswordCallback) callback).setPassword(password);
                    Arrays.fill(password, ' ');
                } else {
                    throw new UnsupportedCallbackException(callback);
                }
            }
        }

    }

}

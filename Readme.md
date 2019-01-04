# README

This is a limited implementation of SASL GSSAPI/Kerberos v5 client provider over native SSPI.
The implementation is limited to the usage of the current user credentials for LDAP client connections.
JPMS is required, implementation was tested on OpenJDK 11.
The only external runtime dependency is JNA. 

Licensed under the Apache License, Version 2.0

Simple usage example is available in ClientTest.java
 
Following configuration properties are implemented:
* javax.security.sasl.qop
* javax.security.sasl.server.authentication
* javax.security.sasl.maxbuffer
* javax.security.sasl.sendmaxbuffer

Some limited debug logging is available with java.util.logging

All product names, trademarks and registered trademarks are property of their respective owners.
All company, product and service names used are for identification purposes only.
Use of these names, trademarks and brands does not imply endorsement.

# JDK FIPS support is Broken

## Overview

This document outlines the testing I've done trying to get a working SSLEngine
out of the SunJSSE provider. It doesn't work. It needs significant improvements
on the part of the JDK team to work.

## Required Setup

I use a modified JDK installation. This uses the `java.security` and
`nss.fips.cfg` present in this repository. I disable SELinux, enable FIPS mode,
and run `nssdb-setup.sh` to create `/nssdb`. Run `chmod 777 -R /nssdb` to bypass
permissions issues.

(This is likely a side effect of my running as root in virtual machines and
 Tomcat wanting to fork to other users. However you can make it work is good.
 The most common side effect of permissions problems is that it'll claim that
 secmod.db is missing. It can't detect actual permissions issues.)

You can either use my modified `java.security` and `nss.fips.cfg` files, or
more simply, pass `-Dcom.redhat.fips=true` on the command line of all Java
programs that need to run in FIPS mode with the FIPS providers.

## Tests

### TomcatJSS FIPS adapter

In [this tree](https://github.com/cipherboy/TomcatJSS/tree/fips-context) is a
clone of TomcatJSS modified to utilize the SunJSSE and SunPKCS11-NSS-FIPS
providers. This loads into Tomcat when built and installed the usual way:

    ./build.sh --with-commit-id --with-timestamp && dnf install /path/to/new-tomcatjss.rpm

This can be used in conjunction with a Tomcat-only [PKI installation](https://github.com/dogtagpki/pki/blob/master/docs/installation/Installing_Basic_PKI_Server.md):

    dnf module enable pki-core
    dnf install pki-server
    pki-server create tomcat@pki

Replace `server.xml` in `/var/lib/tomcats/pki/conf` with the copy in this
tree.

You can run it with:

    pki-server run tomcat@pki

In a separate terminal on the same VM (so localhost will be the resolved
hostname):

    [root@localhost /]# wget https://localhost:8443
    --2019-12-05 10:38:42--  https://localhost:8443/
    Resolving localhost (localhost)... 127.0.0.1
    Connecting to localhost (localhost)|127.0.0.1|:8443... connected.
    GnuTLS: A TLS fatal alert has been received.
    GnuTLS: received alert [80]: Internal error
    Unable to establish SSL connection.
    [root@localhost /]#

But that fails:

     Dec 05, 2019 10:41:44 AM org.apache.tomcat.util.net.NioEndpoint$SocketProcessor doRun
    SEVERE:
    java.lang.RuntimeException: sun.security.pkcs11.wrapper.PKCS11Exception: CKR_ATTRIBUTE_VALUE_INVALID
            at sun.security.ssl.Handshaker.checkThrown(Handshaker.java:1519)
            at sun.security.ssl.SSLEngineImpl.checkTaskThrown(SSLEngineImpl.java:528)
            at sun.security.ssl.SSLEngineImpl.readNetRecord(SSLEngineImpl.java:802)
            at sun.security.ssl.SSLEngineImpl.unwrap(SSLEngineImpl.java:766)
            at javax.net.ssl.SSLEngine.unwrap(SSLEngine.java:624)
            at org.apache.tomcat.util.net.SecureNioChannel.handshakeUnwrap(SecureNioChannel.java:475)
                at org.apache.tomcat.util.net.SecureNioChannel.handshake(SecureNioChannel.java:238)
            at org.apache.tomcat.util.net.NioEndpoint$SocketProcessor.doRun(NioEndpoint.java:1356)
            at org.apache.tomcat.util.net.SocketProcessorBase.run(SocketProcessorBase.java:49)
            at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)
            at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)
            at org.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)
            at java.lang.Thread.run(Thread.java:748)
    Caused by: java.security.ProviderException: sun.security.pkcs11.wrapper.PKCS11Exception: CKR_ATTRIBUTE_VALUE_INVALID
            at sun.security.pkcs11.P11KeyPairGenerator.generateKeyPair(P11KeyPairGenerator.java:424)
            at java.security.KeyPairGenerator$Delegate.generateKeyPair(KeyPairGenerator.java:697)
            at sun.security.ssl.ECDHCrypt.<init>(ECDHCrypt.java:65)
            at sun.security.ssl.ServerHandshaker.setupEphemeralECDHKeys(ServerHandshaker.java:1516)
            at sun.security.ssl.ServerHandshaker.trySetCipherSuite(ServerHandshaker.java:1311)
            at sun.security.ssl.ServerHandshaker.chooseCipherSuite(ServerHandshaker.java:1108)
            at sun.security.ssl.ServerHandshaker.clientHello(ServerHandshaker.java:814)
            at sun.security.ssl.ServerHandshaker.processMessage(ServerHandshaker.java:221)
            at sun.security.ssl.Handshaker.processLoop(Handshaker.java:1037)
            at sun.security.ssl.Handshaker$1.run(Handshaker.java:970)
            at sun.security.ssl.Handshaker$1.run(Handshaker.java:967)
            at java.security.AccessController.doPrivileged(Native Method)
            at sun.security.ssl.Handshaker$DelegatedTask.run(Handshaker.java:1459)
            at org.apache.tomcat.util.net.SecureNioChannel.tasks(SecureNioChannel.java:423)
            at org.apache.tomcat.util.net.SecureNioChannel.handshakeUnwrap(SecureNioChannel.java:483)
            ... 7 more
    Caused by: sun.security.pkcs11.wrapper.PKCS11Exception: CKR_ATTRIBUTE_VALUE_INVALID
            at sun.security.pkcs11.wrapper.PKCS11.C_GenerateKeyPair(Native Method)
            at sun.security.pkcs11.P11KeyPairGenerator.generateKeyPair(P11KeyPairGenerator.java:416)
            ... 21 more

So something is wrong internally to the JDK. This happens for all ECDH cipher
suites. DH cipher suites fail with a similar stack trace:

    Dec 05, 2019 11:10:01 AM org.apache.tomcat.util.net.NioEndpoint$SocketProcessor doRun
    SEVERE:
    java.lang.RuntimeException: sun.security.pkcs11.wrapper.PKCS11Exception: CKR_ATTRIBUTE_VALUE_INVALID
        at sun.security.ssl.Handshaker.checkThrown(Handshaker.java:1519)
        at sun.security.ssl.SSLEngineImpl.checkTaskThrown(SSLEngineImpl.java:528)
        at sun.security.ssl.SSLEngineImpl.readNetRecord(SSLEngineImpl.java:802)
        at sun.security.ssl.SSLEngineImpl.unwrap(SSLEngineImpl.java:766)
        at javax.net.ssl.SSLEngine.unwrap(SSLEngine.java:624)
        at org.apache.tomcat.util.net.SecureNioChannel.handshakeUnwrap(SecureNioChannel.java:475)
        at org.apache.tomcat.util.net.SecureNioChannel.handshake(SecureNioChannel.java:238)
        at org.apache.tomcat.util.net.NioEndpoint$SocketProcessor.doRun(NioEndpoint.java:1356)
        at org.apache.tomcat.util.net.SocketProcessorBase.run(SocketProcessorBase.java:49)
        at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)
        at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)
        at org.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)
        at java.lang.Thread.run(Thread.java:748)
    Caused by: java.security.ProviderException: sun.security.pkcs11.wrapper.PKCS11Exception: CKR_ATTRIBUTE_VALUE_INVALID
        at sun.security.pkcs11.P11KeyPairGenerator.generateKeyPair(P11KeyPairGenerator.java:424)
        at java.security.KeyPairGenerator$Delegate.generateKeyPair(KeyPairGenerator.java:697)
        at sun.security.ssl.DHCrypt.generateDHPublicKeySpec(DHCrypt.java:253)
        at sun.security.ssl.DHCrypt.<init>(DHCrypt.java:133)
        at sun.security.ssl.DHCrypt.<init>(DHCrypt.java:103)
        at sun.security.ssl.ServerHandshaker.setupEphemeralDHKeys(ServerHandshaker.java:1501)
        at sun.security.ssl.ServerHandshaker.trySetCipherSuite(ServerHandshaker.java:1288)
        at sun.security.ssl.ServerHandshaker.chooseCipherSuite(ServerHandshaker.java:1108)
        at sun.security.ssl.ServerHandshaker.clientHello(ServerHandshaker.java:814)
        at sun.security.ssl.ServerHandshaker.processMessage(ServerHandshaker.java:221)
        at sun.security.ssl.Handshaker.processLoop(Handshaker.java:1037)
        at sun.security.ssl.Handshaker$1.run(Handshaker.java:970)
        at sun.security.ssl.Handshaker$1.run(Handshaker.java:967)
        at java.security.AccessController.doPrivileged(Native Method)
        at sun.security.ssl.Handshaker$DelegatedTask.run(Handshaker.java:1459)
        at org.apache.tomcat.util.net.SecureNioChannel.tasks(SecureNioChannel.java:423)
        at org.apache.tomcat.util.net.SecureNioChannel.handshakeUnwrap(SecureNioChannel.java:483)
        ... 7 more
    Caused by: sun.security.pkcs11.wrapper.PKCS11Exception: CKR_ATTRIBUTE_VALUE_INVALID
        at sun.security.pkcs11.wrapper.PKCS11.C_GenerateKeyPair(Native Method)
        at sun.security.pkcs11.P11KeyPairGenerator.generateKeyPair(P11KeyPairGenerator.java:416)
        ... 23 more

If the ciphersuites aren't correct, they usually show up as a failure to
connect with no stacktrace.

Sometimes it is nice to run the JVM directly so you can specify alternative flags:

     /usr/lib/jvm/java/bin/java -Djava.security.debug=all -Djavax.net.debug=all -classpath /usr/share/tomcat/bin/bootstrap.jar:/usr/share/tomcat/bin/tomcat-juli.jar:/usr/lib/java/commons-daemon.jar -Dcatalina.base=/var/lib/tomcats/pki -Dcatalina.home=/usr/share/tomcat -Djava.endorsed.dirs= -Djava.io.tmpdir=/var/lib/tomcats/pki/temp org.apache.catalina.startup.Bootstrap start

Note that Tomcat forks, destroying environment variables, so any NSS specific
debugging options only work for initial JDK startup:

    export NSPR_LOG_FILE=/tmp/pkcs11.log
    export NSPR_LOG_MODULES=all:5
    export NSS_DEBUG_PKCS11_MODULE="NSS Internal PKCS #11 Module"

### Basic Sanity Tests

There's various Java source files in the `sanity` directory. These were used
to work around various issues and as PoCs. Notably, forced introspection of
supported cipher suites shows that it supports very few and doesn't work.

Note that you can't add the pk11-kit-trust module into any NSS DB used by JDK
because it fails with an exception like:

    java.lang.RuntimeException: FIPS flag set for non-internal module: /usr/share/pki/lib/p11-kit-trust.so, p11-kit-trust
        at sun.security.pkcs11.Secmod$Module.<init>(Secmod.java:408)
        at sun.security.pkcs11.Secmod.nssGetModuleList(Native Method)
        at sun.security.pkcs11.Secmod.getModules(Secmod.java:248)
        at sun.security.pkcs11.SunPKCS11.<init>(SunPKCS11.java:225)
        at sun.security.pkcs11.SunPKCS11.<init>(SunPKCS11.java:103)
        at sun.reflect.NativeConstructorAccessorImpl.newInstance0(Native Method)
        at sun.reflect.NativeConstructorAccessorImpl.newInstance(NativeConstructorAccessorImpl.java:62)
        at sun.reflect.DelegatingConstructorAccessorImpl.newInstance(DelegatingConstructorAccessorImpl.java:45)
        at java.lang.reflect.Constructor.newInstance(Constructor.java:423)
        at sun.security.jca.ProviderConfig$2.run(ProviderConfig.java:224)
        at sun.security.jca.ProviderConfig$2.run(ProviderConfig.java:206)
        at java.security.AccessController.doPrivileged(Native Method)
        at sun.security.jca.ProviderConfig.doLoadProvider(ProviderConfig.java:206)
        at sun.security.jca.ProviderConfig.getProvider(ProviderConfig.java:187)
        at sun.security.jca.ProviderList.getProvider(ProviderList.java:233)
        at sun.security.jca.ProviderList.getIndex(ProviderList.java:263)
        at sun.security.jca.ProviderList.getProviderConfig(ProviderList.java:247)
        at sun.security.jca.ProviderList.getProvider(ProviderList.java:253)
        at java.security.Security.getProvider(Security.java:483)
        at sun.security.ssl.SunJSSE.<init>(SunJSSE.java:140)
        at sun.security.ssl.SunJSSE.<init>(SunJSSE.java:123)
        at com.sun.net.ssl.internal.ssl.Provider.<init>(Provider.java:51)
        at sun.reflect.NativeConstructorAccessorImpl.newInstance0(Native Method)
        at sun.reflect.NativeConstructorAccessorImpl.newInstance(NativeConstructorAccessorImpl.java:62)
        at sun.reflect.DelegatingConstructorAccessorImpl.newInstance(DelegatingConstructorAccessorImpl.java:45)
        at java.lang.reflect.Constructor.newInstance(Constructor.java:423)
        at sun.security.jca.ProviderConfig$2.run(ProviderConfig.java:224)
        at sun.security.jca.ProviderConfig$2.run(ProviderConfig.java:206)
        at java.security.AccessController.doPrivileged(Native Method)
        at sun.security.jca.ProviderConfig.doLoadProvider(ProviderConfig.java:206)
        at sun.security.jca.ProviderConfig.getProvider(ProviderConfig.java:187)
        at sun.security.jca.ProviderList.getProvider(ProviderList.java:233)
        at sun.security.jca.ProviderList.getIndex(ProviderList.java:263)
        at sun.security.jca.ProviderList.getProviderConfig(ProviderList.java:247)
        at sun.security.jca.ProviderList.getProvider(ProviderList.java:253)
        at sun.security.jca.GetInstance.getService(GetInstance.java:81)
        at sun.security.jca.GetInstance.getInstance(GetInstance.java:206)
        at java.security.Security.getImpl(Security.java:713)
        at java.security.KeyStore.getInstance(KeyStore.java:896)
        at Client.init(Client.java:271)
        at Client.main(Client.java:405)
    ProviderConfig: Recursion loading provider: com.sun.net.ssl.internal.ssl.Provider('SunPKCS11-NSS-FIPS')
    java.lang.Exception: Call trace
        at sun.security.jca.ProviderConfig.getProvider(ProviderConfig.java:180)
        at sun.security.jca.ProviderList.getProvider(ProviderList.java:233)
        at sun.security.jca.ProviderList.getIndex(ProviderList.java:263)
        at sun.security.jca.ProviderList.getProviderConfig(ProviderList.java:247)
        at sun.security.jca.ProviderList.getProvider(ProviderList.java:253)
        at java.security.Security.getProvider(Security.java:483)
        at sun.security.ssl.SunJSSE.<init>(SunJSSE.java:140)
        at sun.security.ssl.SunJSSE.<init>(SunJSSE.java:123)
        at com.sun.net.ssl.internal.ssl.Provider.<init>(Provider.java:51)
        at sun.reflect.NativeConstructorAccessorImpl.newInstance0(Native Method)
        at sun.reflect.NativeConstructorAccessorImpl.newInstance(NativeConstructorAccessorImpl.java:62)
        at sun.reflect.DelegatingConstructorAccessorImpl.newInstance(DelegatingConstructorAccessorImpl.java:45)
        at java.lang.reflect.Constructor.newInstance(Constructor.java:423)
        at sun.security.jca.ProviderConfig$2.run(ProviderConfig.java:224)
        at sun.security.jca.ProviderConfig$2.run(ProviderConfig.java:206)
        at java.security.AccessController.doPrivileged(Native Method)
        at sun.security.jca.ProviderConfig.doLoadProvider(ProviderConfig.java:206)
        at sun.security.jca.ProviderConfig.getProvider(ProviderConfig.java:187)
        at sun.security.jca.ProviderList.getProvider(ProviderList.java:233)
        at sun.security.jca.ProviderList.getIndex(ProviderList.java:263)
        at sun.security.jca.ProviderList.getProviderConfig(ProviderList.java:247)
        at sun.security.jca.ProviderList.getProvider(ProviderList.java:253)
        at sun.security.jca.GetInstance.getService(GetInstance.java:81)
        at sun.security.jca.GetInstance.getInstance(GetInstance.java:206)
        at java.security.Security.getImpl(Security.java:713)
        at java.security.KeyStore.getInstance(KeyStore.java:896)
        at Client.init(Client.java:271)
        at Client.main(Client.java:405)

### Oracle Sanity Test

Oracle published a SSLEngine sanity check. I've modified it for using these
providers and to output additional logging information. It doesn't work; the
handshake stalls. This is available under the `oracle` directory.

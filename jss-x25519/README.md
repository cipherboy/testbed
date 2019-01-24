# Usage

To use on the v4.5.x branch:

    ./run.sh <hostname> <port>

To use on the v4.4.x branch:

1. Edit the classpath to remove slf4j and glassfish jars.
2. Change `InitializationValues` to `CryptoManager.InitializationValues` in `TriggerClientHello.java`.
3. Change `org.mozilla.jss.ssl.CipherPolicy.DOMESTIC` to `org.mozilla.jss.ssl.SSLSocket.CipherPolicy.DOMESTIC` in `TriggerClientHello.java`.

Then:

    ./run.sh <hostname> <port>

# Notes

    - It is suggested to capture the handshake with tcpdump:

        tcpdump -i <interface_name> -w output.pcap

    And then read the contents of the Client Hello packet.

    - The handshake is expected to fail for one of a multitude of reasons, however, as long as the Client Hello is sent, this is sufficient for testing that `x25519` is removed.

    - The groups are listed under `Secure Sockets Layer`, `TLSv1.2 Record Layer: Handshake Protocol: Client Hello`, `Handshake Protocol: Client Hello`, `Extension: supported_groups`, `Supported Groups`. `x25519` should not be listed.

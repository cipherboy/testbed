Instructions:

To generate certificates for the first time, run:

    create.sh

After this, all certificates will be created and there will be no need to
rerun this command, except on a different system. This creates the following
certificates:

    - A trusted root certificate (`ca_root.crt`) -- `root`
    - A valid sub certificate (`ca_sub.crt`) -- `sub`
    - A valid website signed by the root (`sslserver-a.crt`) -- `a`
    - A valid website signed by the sub (`sslserver-b.crt`) -- `b`
    - An invalid website (`sslserver-c.crt`) -- `c`
    - An untrusted root certificate (`compromised_root.crt`) -- not available from verify.sh
    - An untrusted sub certificate (`compromised_sub.crt`) -- `csub`
    - An invalid website signed by the untrusted root (`sslserver-d.crt`) -- `d`
    - An invalid website signed by the untrusted sub (`sslserver-e.crt`) -- `e`

Corresponding p12 files are created for all of these certificates as well.

To test PKICertImport.bash, use the `verify.sh` interface. Specify a list of
certificates to try importing:

    verify.sh root sub a b c csub d e

They'll be imported in order specified. So, the following will import all
three certificates:

    verify.sh root sub b

This will complete successfully as well:

    verify.sh root b sub
    
But sub is already imported when b is imported (as we're importing PKCS12
chains). However, this will fail because the root isn't trusted:

    verify.sh b

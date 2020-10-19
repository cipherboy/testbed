var extractable = true;

async function generate(rsa, bits, curve, usage) {
    if (usage === undefined || usage === null) {
        usage = ['sign', 'verify'];
    }

    var algorithm = {};
    if (rsa) {
        if (usage.indexOf('sign') !== -1 || usage.indexOf('verify') !== -1 ) {
            algorithm.name = "RSA-PSS";
        } else {
            algorithm.name = "RSA-OAEP";
        }
        algorithm.modulusLength = +bits;
        algorithm.publicExponent = new Uint8Array([1, 0, 1]);
        algorithm.hash = {"name": "SHA-256"};
    } else {
        algorithm.name = "ECDSA";
        algorithm.namedCurve = curve;
    }

    console.log(usage, algorithm);
    var keys = await crypto.subtle.generateKey(algorithm, extractable, usage);
    return keys;
}

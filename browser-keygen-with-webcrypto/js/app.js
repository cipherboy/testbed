var exportable = true;

async function generate(rsa, bits, curve) {
    var algorithm = {};
    if (rsa) {
        algorithm.name = "RSA-PSS";
        algorithm.modulusLength = +bits;
        algorithm.publicExponent = new Uint8Array([1, 0, 1]);
        algorithm.hash = "SHA-256";
    } else {
        algorithm.name = "ECDSA";
        algorithm.namedCurve = curve;
    }
    console.log(algorithm);
    var keys = await crypto.subtle.generateKey(algorithm, exportable, ['sign', 'verify']);
    console.log(keys);
    return keys;
}

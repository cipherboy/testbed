import React from 'react';
import './App.css';

import * as asn1js from "asn1js";
import { arrayBufferToString, toBase64 } from "pvutils";
import {
  Attribute, AttributeTypeAndValue, CertificationRequest,
  Certificate, Extension, Extensions
} from "pkijs";

class KeyGen extends React.Component {
  constructor(props) {
    super(props);

    this.state = {
      algorithm: "",
      curve: "",
      bits: "",
      usage: ['sign', 'verify'],
    };
  }

  setAlgorithm(event) {
    var value = event.target.value;
    this.setState((state) => Object.assign({}, state, { algorithm: value }));
  }

  setKeySize(event) {
    var bits = +event.target.value;
    this.setState((state) => Object.assign({}, state, { bits: bits }));
  }

  setCurve(event) {
    var curve = event.target.value;
    this.setState((state) => Object.assign({}, state, { curve: curve }));
  }

  async generate() {
    var algorithm = {};
    if (this.state.algorithm === "RSA") {
      if (this.state.usage.indexOf('sign') !== -1 || this.state.usage.indexOf('verify') !== -1 ) {
          algorithm.name = "RSA-PSS";
      } else {
          algorithm.name = "RSA-OAEP";
      }
      algorithm.modulusLength = +this.state.bits;
      algorithm.publicExponent = new Uint8Array([1, 0, 1]);
      algorithm.hash = {"name": "SHA-256"};
    } else {
      algorithm.name = "ECDSA";
      algorithm.namedCurve = this.state.curve;
    }

    var keys = await crypto.subtle.generateKey(algorithm, true /* extractable */, this.state.usage);
    this.props.setKeys(keys);
  }
}

class CAKeyGen extends KeyGen {
  render() {
    return (
      <div id="ca-keygen">
        <h3>(DEMO ONLY) Generate CA Keys (DEMO ONLY)</h3>
        <p>
          This won't be here ordinarily. This just exists to make this demo
          testable with <a href="https://fortifyapp.com/">Fortify</a>, without
          needing a RHCS instance.
        </p>
        <div className="input-field">
          <label htmlFor="ca-keytype">CA Key Type</label>
          <select name="ca-keytype" onChange={ (event) => this.setAlgorithm(event) } value={ this.state.algorithm }>
            <option default disabled value="">---</option>
            <option value="RSA">RSA</option>
            <option value="ECDSA">ECDSA</option>
          </select>
        </div>
        {
          this.state.algorithm === "RSA"
          ? <div className="input-field">
              <label htmlFor="ca-keysize-rsa">CA Key Size</label>
              <select name="ca-keysize-rsa" onChange={ (event) => this.setKeySize(event) } value={ "" + this.state.bits }>
                <option default disabled value="">---</option>
                <option value="2048">2048</option>
                <option value="3072">3072</option>
                <option value="4096">4096</option>
              </select>
            </div>
          : null
        }
        {
          this.state.algorithm === "ECDSA"
          ? <div className="input-field">
              <label htmlFor="ca-keysize-ecdsa">CA Key Curve</label>
              <select name="ca-keysize-ecdsa" onChange={ (event) => this.setCurve(event) } value={ "" + this.state.curve }>
                <option default disabled value="">---</option>
                <option value="P-256">P-256</option>
                <option value="P-384">P-384</option>
                <option value="P-521">P-521</option>
              </select>
            </div>
          : null
        }
        {
          (this.state.algorithm === "RSA" && this.state.bits !== "") ||
          (this.state.algorithm === "ECDSA" && this.state.curve !== "")
          ? <button onClick={ () => this.generate() }>Generate</button>
          : null
        }
      </div>
    );
  }
}

class CertKeyGen extends KeyGen {
  render() {
    return (
      <div id="cert-keygen">
        <h3>Generate Cert Keys</h3>
        <p>
          When using fortify, these certificates should be generated onto the
          card itself.
        </p>
        <div className="input-field">
          <label htmlFor="cert-keytype">Cert Key Type</label>
          <select name="cert-keytype" onChange={ (event) => this.setAlgorithm(event) } value={ this.state.algorithm }>
            <option default disabled value="">---</option>
            <option value="RSA">RSA</option>
            <option value="ECDSA">ECDSA</option>
          </select>
        </div>
        {
          this.state.algorithm === "RSA"
          ? <div className="input-field">
              <label htmlFor="cert-keysize-rsa">Cert Key Size</label>
              <select name="cert-keysize-rsa" onChange={ (event) => this.setKeySize(event) } value={ "" + this.state.bits }>
                <option default disabled value="">---</option>
                <option value="2048">2048</option>
                <option value="3072">3072</option>
                <option value="4096">4096</option>
              </select>
            </div>
          : null
        }
        {
          this.state.algorithm === "ECDSA"
          ? <div className="input-field">
              <label htmlFor="cert-keysize-ecdsa">Cert Key Curve</label>
              <select name="cert-keysize-ecdsa" onChange={ (event) => this.setCurve(event) } value={ "" + this.state.curve }>
                <option default disabled value="">---</option>
                <option value="P-256">P-256</option>
                <option value="P-384">P-384</option>
                <option value="P-521">P-521</option>
              </select>
            </div>
          : null
        }
        {
          (this.state.algorithm === "RSA" && this.state.bits !== "") ||
          (this.state.algorithm === "ECDSA" && this.state.curve !== "")
          ? <button onClick={ () => this.generate() }>Generate</button>
          : null
        }
      </div>
    );
  }
}

class CSRForm extends React.Component {
  constructor(props) {
    super(props);

    this.state = {
      subject: null,
      city: null,
      state: null,
      country: null,
      orgunit: null,
      org: null,
    };
  }

  setFormValue(field, value) {
    var changed = {};
    changed[field] = value;

    this.setState((state) => Object.assign({}, state, changed));
  }

  async generate() {
    let pkcs10 = new CertificationRequest();

    pkcs10.version = 0;

    // Set the CSR's Subject
    pkcs10.subject.typesAndValues.push(
      new AttributeTypeAndValue({
        type: "2.5.4.3",
        value: new asn1js.PrintableString({ value: this.state.subject }),
      })
    );

    // Import key
    pkcs10.subjectPublicKeyInfo.importKey(this.props.cert_keys.publicKey);

    // Set the SKI identifier
    pkcs10.attributes = [];
    var checksum = await crypto.subtle.digest(
      { name: "SHA-256" },
      pkcs10.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex
    );

    pkcs10.attributes.push(
      new Attribute({
        type: "1.2.840.113549.1.9.14", // pkcs-9-at-extensionRequest
        values: [(
          new Extensions({
            extensions: [
              new Extension({
                extnID: "2.5.29.14",
                critical: false,
                extnValue: (new asn1js.OctetString({ valueHex: checksum })).toBER(false)
              })
            ]
          })).toSchema()
        ]
      })
    );

    // Self-sign to finish the CSR.
    await pkcs10.sign(this.props.cert_keys.privateKey, "SHA-256");

    // var bytes = await pkcs10.toSchema().toBER(false);
    this.props.setCSR(pkcs10);
  }

  render() {
    return (
      <form id="cert-csr-form" onSubmit={ (event) => { event.preventDefault() ; this.generate() } }>
        <h3>Generate Certificate Signing Request</h3>
        <p>
          In the future, this section will include additional fields and allow
          the user to specify a local CSR to read via a form.
        </p>
        <div className="input-field">
          <label htmlFor="Subject">Subject</label>
          <input name="Subject" type="text" value={ this.subject } onChange={ (event) => this.setFormValue("subject", event.target.value) } />
        </div>
        <button>Generate CSR</button>
      </form>
    );
  }
}

class SignForm extends React.Component {
  async generate() {
    var signed = new Certificate();

    console.log(signed, signed.toJSON());

    // Serial number is required.
    signed.version = 0;
    signed.serialNumber = new asn1js.Integer({ value: 42 });

    // Keep cert expiration short and simple.
    var expiration = new Date();
    expiration.setDate(expiration.getDate() + 5);
    signed.notBefore.value = new Date();
    signed.notAfter.value = expiration;

    // Add faked issuer information.
    signed.issuer.typesAndValues.push(new AttributeTypeAndValue({
        type: "2.5.4.3", // Country name
        value: new asn1js.PrintableString({ value: "RHCS-DEMO" })
    }));

    signed.subject = this.props.csr.subject;
    signed.subjectPublicKeyInfo = this.props.csr.subjectPublicKeyInfo;

    console.log(signed, signed.toJSON());
    console.log(signed, toBase64(arrayBufferToString(signed.encodeTBS().toBER(false))));

    // Self-sign to finish the certificate.
    await signed.sign(this.props.ca_keys.privateKey, "SHA-256");
    // await signed.verify(this.props.ca_keys.publicKey);

    console.log(signed.toJSON());

    var bytes = await signed.toSchema().toBER(false);
    this.props.setCert(bytes);
  }

  render () {
    return (
      <div id="cert-submission">
        <h3>Sign CSR</h3>
        <p>
          In the future, this will submit the CSR with the correct profile and
          additional data to RHCS. Currently we're doing it locally to test if
          this will work with smart cards.
        </p>
        <button onClick={ () => this.generate() }>Sign CSR with CA</button>
      </div>
    );
  }
}

class App extends React.Component {
  constructor(props) {
    super(props);

    this.state = {
      ca_keys: null,
      cert_keys: null,
      csr: null,
      cert: null,
    };
  }

  setCAKeys(keys) {
    this.setState((state) => Object.assign({}, state, { ca_keys: keys }));
  }

  setCertKeys(keys) {
    this.setState((state) => Object.assign({}, state, { cert_keys: keys }));
  }

  setCSR(csr) {
    this.setState((state) => Object.assign({}, state, { csr }));
  }

  setCert(cert) {
    this.setState((state) => Object.assign({}, state, { cert }));
  }

  toPEM(data) {
    var result = "";
    var line = "";

    for (let char of data) {
      if (line.length >= 64) {
        result += line += "\r\n";
        line = "";
      }

      line += char;
    }

    if (line !== "") {
      result += line += "\r\n";
    }

    return result;
  }

  render() {
    return (
      <div className="App">
        {
          this.state.ca_keys === null
          ? <CAKeyGen setKeys={ this.setCAKeys.bind(this) } />
          : <>
              <div id="ca-keygen">
                <h3>(DEMO ONLY) Remove CA Keys (DEMO ONLY)</h3>
                <button onClick={ () => this.setCAKeys(null) }>Delete CA Keys</button>
              </div>
              {
                this.state.cert_keys === null
                ? <CertKeyGen setKeys={ this.setCertKeys.bind(this) } />
                : <>
                    <div id="cert-keygen">
                      <h3>Remove Cert Keys</h3>
                      <button onClick={ () => this.setCertKeys(null) }>Delete Cert Keys</button>
                    </div>
                    {
                      this.state.csr === null
                      ? <CSRForm cert_keys={ this.state.cert_keys } setCSR={ this.setCSR.bind(this) } />
                      : <>
                        {
                          this.state.cert === null
                          ? <SignForm ca_keys={ this.state.ca_keys } cert_keys={ this.state.cert_keys } csr={ this.state.csr } setCert={ this.setCert.bind(this) } />
                          : <>
                              <h3>Now check that the keys (CA and Cert) were created on the card.</h3>
                              <p>For reference, this is the signed end-entity certificate below. For now, the generated CA certificate isn't included.</p>
                              <pre>
{
  "-----BEGIN CERTIFICATE-----\r\n" +
  this.toPEM(toBase64(arrayBufferToString(this.state.cert))) +
  "-----END CERTIFICATE-----"
}
                              </pre>
                            </>
                        }
                        </>
                    }
                  </>
              }
            </>
        }
      </div>
    );
  }
}

export default App;

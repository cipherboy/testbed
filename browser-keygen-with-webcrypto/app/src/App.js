import React from 'react';
import './App.css';

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
          testable with <a href="https://fortifyapp.com/">Fortify</a>.
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

  generate() {
    return null;
  }

  render() {
    return (
      <div id="cert-csr-form">
        <h3>Certificate Signing Request</h3>
        <p>
          In the future, this section will include additional fields and allow
          the user to specify a CSR to upload.
        </p>
        <div className="input-field">
          <label htmlFor="Subject">Subject</label>
          <input name="Subject" type="text" value={ this.subject } onChange={ (event) => this.setFormValue("subject", event.target.value) } />
        </div>
        <div className="input-field">
          <label htmlFor="City">City</label>
          <input name="City" type="text" value={ this.city } onChange={ (event) => this.setFormValue("city", event.target.value) } />
        </div>
        <div className="input-field">
          <label htmlFor="State">State</label>
          <input name="State" type="text" value={ this.state } onChange={ (event) => this.setFormValue("state", event.target.value) } />
        </div>
        <div className="input-field">
          <label htmlFor="Country">Country</label>
          <input name="Country" type="text" value={ this.country } onChange={ (event) => this.setFormValue("country", event.target.value) } />
        </div>
        <div className="input-field">
          <label htmlFor="OrgUnit">Organization Unit</label>
          <input name="OrgUnit" type="text" value={ this.orgunit } onChange={ (event) => this.setFormValue("orgunit", event.target.value) } />
        </div>
        <div className="input-field">
          <label htmlFor="Org">Organization</label>
          <input name="Org" type="text" value={ this.org } onChange={ (event) => this.setFormValue("org", event.target.value) } />
        </div>
        <button onClick={ () => this.generate() }>Generate CSR</button>
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
    };
  }

  setCAKeys(keys) {
    this.setState((state) => Object.assign({}, state, { ca_keys: keys }));
  }

  setCertKeys(keys) {
    this.setState((state) => Object.assign({}, state, { cert_keys: keys }));
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
                    <CSRForm />
                  </>
              }
            </>
        }
      </div>
    );
  }
}

export default App;

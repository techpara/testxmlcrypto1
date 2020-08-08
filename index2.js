/*jslint node: true*/

var fs = require('fs');
var path = require('path');
var xml_crypto_1 = require("xml-crypto");
var dom = require('xmldom').DOMParser
	var x509Certificate="MIIEGTCCAwGgAwIBAgIUAnE9HtD9wEL5aKZ2Bo2lK2REvugwDQYJKoZIhvcNAQELBQAwgZsxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJWQTEQMA4GA1UEBwwHTm9yZm9sazEXMBUGA1UECgwOUmVjeWNsaW5nUGVya3MxCzAJBgNVBAsMAklUMR8wHQYDVQQDDBZhcHAucmVjeWNsaW5ncGVya3MuY29tMSYwJAYJKoZIhvcNAQkBFhdpbmZvQHJlY3ljbGluZ3BlcmtzLmNvbTAeFw0yMDA4MDYxMTExMjhaFw0yMzA1MDMxMTExMjhaMIGbMQswCQYDVQQGEwJVUzELMAkGA1UECAwCVkExEDAOBgNVBAcMB05vcmZvbGsxFzAVBgNVBAoMDlJlY3ljbGluZ1BlcmtzMQswCQYDVQQLDAJJVDEfMB0GA1UEAwwWYXBwLnJlY3ljbGluZ3BlcmtzLmNvbTEmMCQGCSqGSIb3DQEJARYXaW5mb0ByZWN5Y2xpbmdwZXJrcy5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4460mU0tYEJEns5gDGAtCNYR0M5QWPXqKh64Q9Nm8tOxCspKXBBttPeqb8U0RgnKeDO4zJiLOdi6dbYsdB9TzpJyf//ieywHihgDtLxbdN7Qy+lM0jiPpx9bh/PJi3FwOHR3ZdsSxl7p0dKGXWhyyjztB4tIG6VjFg2h9EtrV47ZLGSsU1q26h6wMgWaQkZ5kAssFlzjFgudAH+ggpihmxaBJvvDB2A9fJSagE/Oq4bL7uqD+FOFbK8ngtXe8rzuXzLI/Ivbprg7/vUwNNZpjaQa7CtrtOk2vsRmMB1FnGOu8iF/sSld/3v24v7sOT/BHnRWa3RJObiQFzccMPGPrAgMBAAGjUzBRMB0GA1UdDgQWBBS/7+XQwMhtxM+rgEh/9w5yQLkyijAfBgNVHSMEGDAWgBS/7+XQwMhtxM+rgEh/9w5yQLkyijAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQA87Nbv3dv/gR9mqtGVfZ3JyS4o2vGmuHWvn8hAcBxALuwxwmXbpjJMdmVOm3nG25TpRsibmINUJ4Y1tCLdTjY6YAyeESkjjNAi+38Xyv2tRWs+9iE7huvK/1FVPK1DY0grB3TEGaLL8SQBwUl/RU4/XdiM9QY5bD59V5Ae+boF4Ym18enek5FzEyFsnO3zONsMVqGOh0weVldozGIOQlEr3wuqT+PyhTzxmIXNXAN4cUFs6fQWAChGL/43yItX3CpzxvM89GSScrzMV95R6awf1XK55R4/sTbfNajsjszQUi3yV/HyWOb2qInyqewjKHUAWIFosYN6DYZ5lq3aX74M";
	var SignedXml = require('xml-crypto').SignedXml	  ;
	var xml =fs.readFileSync('./security/unsigned-sample-response.xml', 'utf-8');
	var sig = new SignedXml()
	sig.signingKey =  fs.readFileSync('./security/RP-2048-RSA256-PrivateKey.pem');
	sig.keyInfoProvider = new MyKeyInfo(x509Certificate);
  sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
  sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
	sig.addReference("/*[local-name(.)='Response']",[
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
    "http://www.w3.org/2001/10/xml-exc-c14n#"],"http://www.w3.org/2001/04/xmlenc#sha256");
	sig.computeSignature(xml);
	var signedXML = sig.getSignedXml();
	console.log(signedXML);
	fs.writeFileSync("./security/signed-sample-sml.xml", signedXML)
	//-------------------------
	var select = require('xml-crypto').xpath
	  , dom = require('xmldom').DOMParser
	  , SignedXml = require('xml-crypto').SignedXml
	  , FileKeyInfo = require('xml-crypto').FileKeyInfo  
	 
	var xml = fs.readFileSync("./security/signed-sample-sml.xml").toString()
	var doc = new dom().parseFromString(xml) ;  
	var signature = select(doc, "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
	sig.keyInfoProvider = new FileKeyInfo('./security/RP-X509-RSA256-2048BIT.cer');
	sig.loadSignature(signature.toString());
	var res = sig.checkSignature(xml);
	if (!res)
  { 
    console.log(sig.validationErrors)	
  }
  else
  {
    console.log('--verified--');
  }

	function MyKeyInfo(x509Certificate) {
				this.getKeyInfo = function (key) {
					var prefix = "ds";
					return "<" + prefix + "X509Data><" + prefix + "X509Certificate>" + x509Certificate + "</" + prefix + "X509Certificate></" + prefix + "X509Data>";
				};
				this.getKey = function (keyInfo) {
					return utility_1.default.getPublicKeyPemFromCertificate(x509Certificate).toString();
				};
	}

const axios = require('axios');

const data = {
    name: 'John Doe',
    job: 'Content Writer'
};
var loginResponse = await  idp.createLoginResponse(
			sp, {}, 'post', {}, createTemplateCallback(idp, sp, nameId),1
		);

		loginResponse.entityEndpoint = "https://passport.benefithub.info/saml/post/ac"

console.log(loginResponse);

const createUser = async () => {
    try {
        const res = await axios.post('https://passport.benefithub.info/saml/post/ac', loginResponse);
        console.log(`Status: ${res.status}`);
        console.log('Body: ', res.data);
    } catch (err) {
        console.error(err);
    }
};

createUser();
  
	//	res.render('benefithub-sso-post', loginResponse);
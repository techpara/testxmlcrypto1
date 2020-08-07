/*jslint node: true*/

var fs = require('fs');
var path = require('path');
var xml_crypto_1 = require("xml-crypto");

const nameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
	organizationID = "6835707029513797472",
	nameId = "priteshatgmail",
	binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
	successStatusCode = "urn:oasis:names:tc:SAML:2.0:status:Success",
	spSSOURL = "https://passport.benefithub.info/saml/post/ac",
	entityId = "recyclingperks",
	dataEncryptionAlgorithm = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
	keyEncryptionAlgorithm = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
	signatureAlgorithm  = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
	transformationAlgorithms = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
	
	
	var x509Certificate="MIIDbTCCAlSgAwIBAgIBADANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJ1czELMAkGA1UECAwCVkExFzAVBgNVBAoMDnJlY3ljbGluZ3BlcmtzMRswGQYDVQQDDBJyZWN5Y2xpbmdwZXJrcy5jb20wHhcNMjAwODA1MTUzNTIyWhcNMjEwODA1MTUzNTIyWjBQMQswCQYDVQQGEwJ1czELMAkGA1UECAwCVkExFzAVBgNVBAoMDnJlY3ljbGluZ3BlcmtzMRswGQYDVQQDDBJyZWN5Y2xpbmdwZXJrcy5jb20wggEjMA0GCSqGSIb3DQEBAQUAA4IBEAAwggELAoIBAgC3cIS2Zi60PSIjSaHr1y/2C+F7LWOVIEUAcmBgbYvFdMYU/hOBo4WH/C3iPHPjRx2NAYZiJnMEy/1AQFacYpyknGTpIl8gb43CLM1MJ5lgICPANPq9qA5XkO8KY+IZcp4sL4mL9i5o7QcJd/AV7E1XbrehCvLU5q66CEAQvcgt8qZMbG3lHoOR+3mq82Zetr8IrlbVWIqbuAGJbIcdpGZ/7kkDOivE9ASFTWfmFviW4pjIVQUbM05tmaasad4IGnT1y8uxPcCHETuepSeu4CPLZNg0ZHiSKwpEk3ZlGVVOYY+Lu/R6VfKH2E/JSveE6FxUFRDkQUbNOX8UGy9eKlKqgQIDAQABo1AwTjAdBgNVHQ4EFgQU4JM8SlZLzJYhS84jtinF+PHHSrIwHwYDVR0jBBgwFoAU4JM8SlZLzJYhS84jtinF+PHHSrIwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQIAsfovQVrY44p3enoQyf3+kg+kLrbgXm1tM8nU9JMVE26SgZCXak1EIUBP0Y0MLTQharynkTNjyQ8jVXgKIS1AuCMy/XpQoixXh0b+kpi0h3jmHH7WvvFkQCD5manWn1UGfEyGNHEM684aDw/Zp6WPUXiYCgZAYZ7gZRZInAoNTYP3p+iqnqZ7KKitvEGb/vcYueYO50rsORyCipAtLIFBoczfkqWWVbm3iUhFTbsIaHFE3copHf1+PxiUYsNyCJJU407P+QRpthAB7j9PhWddW3CI9HwzGUpHW/2JVKlmjfB9xyFYhaNJsfFMZYCAaY6lcWW5MvukaTosst81PZMdWE4=";
	var SignedXml = require('xml-crypto').SignedXml	  ;
	var xml =fs.readFileSync('./security/unsigned-sample-response.xml', 'utf-8');
	var sig = new SignedXml()
	sig.signingKey =  fs.readFileSync('./security/private-key.pem');
	sig.keyInfoProvider = new MyKeyInfo(x509Certificate);
	//sig.addReference("/*[local-name(.)='Response']/*[local-name(.)='Assertion']")   ;
	sig.computeSignature(xml);
	var signedXML = sig.getSignedXml();
	console.log(signedXML);
	
	//-------------------------
	var select = require('xml-crypto').xpath
	  , dom = require('xmldom').DOMParser
	  , SignedXml = require('xml-crypto').SignedXml
	  , FileKeyInfo = require('xml-crypto').FileKeyInfo  
	 

	var xml = fs.readFileSync("./security/signed-sample-sml.xml").toString()
	var doc = new dom().parseFromString(xml)    

	var signature = select(doc, "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0]
	//console.log(signature);
	sig.keyInfoProvider = new FileKeyInfo('./security/RP-X509.cer');
	sig.loadSignature(signature);
	var res = sig.checkSignature(xml);
	//console.log(res);

	if (!res) console.log(sig.validationErrors)	


	function MyKeyInfo(x509Certificate) {
				this.getKeyInfo = function (key) {
					var prefix = "ds";
					return "<" + prefix + "X509Data><" + prefix + "X509Certificate>" + x509Certificate + "</" + prefix + "X509Certificate></" + prefix + "X509Data>";
				};
				this.getKey = function (keyInfo) {
					return utility_1.default.getPublicKeyPemFromCertificate(x509Certificate).toString();
				};
	}
package com.nimbusds.oauth2.sdk.assertions.saml2;


import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import junit.framework.TestCase;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.util.Pair;
import org.opensaml.xml.util.XMLHelper;


/**
 * Tests the SAML 2.0 assertion factory and validator.
 */
public class SAML2AssertionTest extends TestCase {


	private static Pair<RSAPublicKey,RSAPrivateKey> generateRSAKeyPair()
		throws NoSuchAlgorithmException {

		KeyPairGenerator keyPairGenerator =KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return new Pair<>((RSAPublicKey)keyPair.getPublic(), (RSAPrivateKey)keyPair.getPrivate());
	}


	private static SecretKey generateHMACKey()
		throws NoSuchAlgorithmException {

		KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSha256");
		return keyGenerator.generateKey();
	}


	public void testCreateAndValidateMinimal_RSA()
		throws Exception {

		Issuer issuer = new Issuer("https://saml.idp.com");
		Subject subject = new Subject("alice@wonderland.net");
		Audience audience = new Audience("https://c2id.com/token");

		SAML2AssertionDetails details = new SAML2AssertionDetails(
			issuer,
			subject,
			audience);

		assertEquals(issuer, details.getIssuer());
		assertEquals(subject, details.getSubject());
		assertTrue(details.getAudience().contains(audience));
		assertEquals(1, details.getAudience().size());
		assertNull(details.getSubjectFormat());
		assertNull(details.getSubjectAuthenticationTime());
		assertNull(details.getSubjectACR());
		assertTrue(details.getExpirationTime().after(new Date()));
		assertNull(details.getNotBeforeTime());
		assertNotNull(details.getIssueTime());
		assertNotNull(details.getID());
		assertNull(details.getClientInetAddress());
		assertNull(details.getAttributeStatement());

		BasicCredential credential = new BasicCredential();
		Pair<RSAPublicKey,RSAPrivateKey> keyPair = generateRSAKeyPair();
		credential.setPublicKey(keyPair.getFirst());
		credential.setPrivateKey(keyPair.getSecond());
		credential.setUsageType(UsageType.SIGNING);

		String xml = SAML2AssertionFactory.createAsString(details, keyPair.getSecond());

		assertFalse(xml.startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));

//		System.out.println(XMLHelper.prettyPrintXML(SAML2AssertionFactory.createAsElement(
//			details,
//			SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256,
//			credential)));

		// Parse back
		SAML2AssertionDetailsVerifier detailsVerifier = new SAML2AssertionDetailsVerifier(new HashSet<>(Collections.singletonList(new Audience("https://c2id.com/token"))));
		SAML2AssertionValidator v = new SAML2AssertionValidator(detailsVerifier);
		assertEquals(detailsVerifier, v.getDetailsVerifier());

		Assertion a = v.validate(xml, issuer, keyPair.getFirst());

		assertNotNull(a.getID());
		assertNotNull(a.getIssueInstant());
		assertEquals(issuer.toString(), a.getIssuer().getValue());
		assertNotNull(a.getSignature());
		assertNull(a.getSubject().getNameID().getFormat());
		assertEquals("alice@wonderland.net", a.getSubject().getNameID().getValue());
		assertEquals(SubjectConfirmation.METHOD_BEARER, a.getSubject().getSubjectConfirmations().get(0).getMethod());
		assertTrue(a.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().getNotOnOrAfter().isAfterNow());
		assertEquals("https://c2id.com/token", a.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().getRecipient());
		assertEquals("https://c2id.com/token", a.getConditions().getAudienceRestrictions().get(0).getAudiences().get(0).getAudienceURI());
		assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", a.getSignature().getSignatureAlgorithm());

		details = SAML2AssertionDetails.parse(a);

		assertEquals(issuer, details.getIssuer());
		assertEquals(subject, details.getSubject());
		assertTrue(details.getAudience().contains(audience));
		assertEquals(1, details.getAudience().size());
		assertNull(details.getSubjectFormat());
		assertNull(details.getSubjectAuthenticationTime());
		assertNull(details.getSubjectACR());
		assertTrue(details.getExpirationTime().after(new Date()));
		assertNull(details.getNotBeforeTime());
		assertNotNull(details.getIssueTime());
		assertNotNull(details.getID());
		assertNull(details.getClientInetAddress());
		assertNull(details.getAttributeStatement());
	}


	public void testCreateAndValidateMinimal_HMAC()
		throws Exception {

		Issuer issuer = new Issuer("https://saml.idp.com");
		Subject subject = new Subject("alice@wonderland.net");
		Audience audience = new Audience("https://c2id.com/token");

		SAML2AssertionDetails details = new SAML2AssertionDetails(
			issuer,
			subject,
			audience);

		assertEquals(issuer, details.getIssuer());
		assertEquals(subject, details.getSubject());
		assertTrue(details.getAudience().contains(audience));
		assertEquals(1, details.getAudience().size());
		assertNull(details.getSubjectFormat());
		assertNull(details.getSubjectAuthenticationTime());
		assertNull(details.getSubjectACR());
		assertTrue(details.getExpirationTime().after(new Date()));
		assertNull(details.getNotBeforeTime());
		assertNotNull(details.getIssueTime());
		assertNotNull(details.getID());
		assertNull(details.getClientInetAddress());
		assertNull(details.getAttributeStatement());

		BasicCredential credential = new BasicCredential();
		SecretKey hmacKey = generateHMACKey();
		credential.setSecretKey(hmacKey);

		String xml = SAML2AssertionFactory.createAsString(details, SignatureConstants.ALGO_ID_MAC_HMAC_SHA256, credential);

		assertFalse(xml.startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));

		// Parse back
		SAML2AssertionDetailsVerifier detailsVerifier = new SAML2AssertionDetailsVerifier(new HashSet<>(Collections.singletonList(new Audience("https://c2id.com/token"))));
		SAML2AssertionValidator v = new SAML2AssertionValidator(detailsVerifier);
		assertEquals(detailsVerifier, v.getDetailsVerifier());

		Assertion a = v.validate(xml, issuer, credential.getSecretKey());

		assertNotNull(a.getID());
		assertNotNull(a.getIssueInstant());
		assertEquals(issuer.toString(), a.getIssuer().getValue());
		assertNotNull(a.getSignature());
		assertNull(a.getSubject().getNameID().getFormat());
		assertEquals("alice@wonderland.net", a.getSubject().getNameID().getValue());
		assertEquals(SubjectConfirmation.METHOD_BEARER, a.getSubject().getSubjectConfirmations().get(0).getMethod());
		assertTrue(a.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().getNotOnOrAfter().isAfterNow());
		assertEquals("https://c2id.com/token", a.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().getRecipient());
		assertEquals("https://c2id.com/token", a.getConditions().getAudienceRestrictions().get(0).getAudiences().get(0).getAudienceURI());
		assertEquals("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", a.getSignature().getSignatureAlgorithm());

		details = SAML2AssertionDetails.parse(a);

		assertEquals(issuer, details.getIssuer());
		assertEquals(subject, details.getSubject());
		assertTrue(details.getAudience().contains(audience));
		assertEquals(1, details.getAudience().size());
		assertNull(details.getSubjectFormat());
		assertNull(details.getSubjectAuthenticationTime());
		assertNull(details.getSubjectACR());
		assertTrue(details.getExpirationTime().after(new Date()));
		assertNull(details.getNotBeforeTime());
		assertNotNull(details.getIssueTime());
		assertNotNull(details.getID());
		assertNull(details.getClientInetAddress());
		assertNull(details.getAttributeStatement());
	}


	public void testCreateAndValidateComplete()
		throws Exception {

		Date now = new Date();

		Issuer issuer = new Issuer("https://saml.idp.com");
		Subject subject = new Subject("alice@wonderland.net");
		String subjectFormat = NameIDType.EMAIL;
		Date subjectAuthTime = new Date(now.getTime() - 24*60*60*1000L);
		ACR subjectACR = new ACR("0");
		List<Audience> audience = Audience.create("https://c2id.com/token", "https://c2id.com");
		Date expirationTime = new Date(now.getTime() + 5*60*1000L);
		Date notBeforeTime = now;
		Date issueTime = now;
		Identifier id = new Identifier();
		InetAddress clientAddress = InetAddress.getByName("192.168.0.1");
		Map<String,List<String>> attrs = new HashMap<>();
		attrs.put("roles", Arrays.asList("audit", "admin"));
		attrs.put("manager", Collections.singletonList("claire"));
		attrs.put("office", Collections.singletonList("A315"));

		SAML2AssertionDetails details = new SAML2AssertionDetails(
			issuer,
			subject, subjectFormat, subjectAuthTime, subjectACR,
			audience,
			expirationTime, notBeforeTime, issueTime,
			id,
			clientAddress,
			attrs);

		assertEquals(issuer, details.getIssuer());
		assertEquals(subject, details.getSubject());
		assertEquals(subjectFormat, details.getSubjectFormat());
		assertEquals(subjectAuthTime, details.getSubjectAuthenticationTime());
		assertEquals(subjectACR, details.getSubjectACR());
		assertEquals(audience, details.getAudience());
		assertEquals(expirationTime, details.getExpirationTime());
		assertEquals(notBeforeTime, details.getNotBeforeTime());
		assertEquals(issueTime, details.getIssueTime());
		assertEquals(id, details.getID());
		assertEquals(clientAddress, details.getClientInetAddress());
		assertEquals(attrs, details.getAttributeStatement());

		BasicCredential credential = new BasicCredential();
		Pair<RSAPublicKey,RSAPrivateKey> keyPair = generateRSAKeyPair();
		credential.setPublicKey(keyPair.getFirst());
		credential.setPrivateKey(keyPair.getSecond());
		credential.setUsageType(UsageType.SIGNING);

		String xml = SAML2AssertionFactory.createAsString(details, keyPair.getSecond());

		assertFalse(xml.startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));

		System.out.println(XMLHelper.prettyPrintXML(SAML2AssertionFactory.createAsElement(
			details,
			SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256,
			credential)));

		// Parse back
		SAML2AssertionDetailsVerifier detailsVerifier = new SAML2AssertionDetailsVerifier(new HashSet<>(Collections.singletonList(new Audience("https://c2id.com/token"))));
		SAML2AssertionValidator v = new SAML2AssertionValidator(detailsVerifier);
		assertEquals(detailsVerifier, v.getDetailsVerifier());

		Assertion a = v.validate(xml, issuer, keyPair.getFirst());

		assertNotNull(a.getID());
		assertNotNull(a.getIssueInstant());
		assertEquals(issuer.toString(), a.getIssuer().getValue());
		assertNotNull(a.getSignature());
		assertEquals(NameIDType.EMAIL, a.getSubject().getNameID().getFormat());
		assertEquals("alice@wonderland.net", a.getSubject().getNameID().getValue());
		assertEquals(SubjectConfirmation.METHOD_BEARER, a.getSubject().getSubjectConfirmations().get(0).getMethod());
		assertTrue(a.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().getNotOnOrAfter().isAfterNow());
		assertEquals("https://c2id.com/token", a.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().getRecipient());
		assertEquals("https://c2id.com/token", a.getConditions().getAudienceRestrictions().get(0).getAudiences().get(0).getAudienceURI());
		assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", a.getSignature().getSignatureAlgorithm());

		details = SAML2AssertionDetails.parse(a);

		assertEquals(issuer, details.getIssuer());
		assertEquals(subject, details.getSubject());
		assertEquals(subjectFormat, details.getSubjectFormat());
		assertEquals(subjectAuthTime, details.getSubjectAuthenticationTime());
		assertEquals(subjectACR, details.getSubjectACR());
		assertEquals(audience, details.getAudience());
		assertEquals(expirationTime, details.getExpirationTime());
		assertEquals(notBeforeTime, details.getNotBeforeTime());
		assertEquals(issueTime, details.getIssueTime());
		assertEquals(id, details.getID());
		assertEquals(clientAddress, details.getClientInetAddress());
		assertEquals(attrs, details.getAttributeStatement());
	}


	public void testMissingSignature()
		throws Exception {

		SAML2AssertionDetails details = new SAML2AssertionDetails(new Issuer("https://c2id.com"), new Subject("alice@wondlerland.net"), new Audience("https://client.com"));

		Assertion assertion = details.toSAML2Assertion();

		SAML2AssertionValidator validator = new SAML2AssertionValidator(new SAML2AssertionDetailsVerifier(new HashSet<>(Collections.singletonList(new Audience("https://client.com")))));

		try {
			validator.validate(assertion, new Issuer("https://c2id.com"), new SecretKeySpec(new byte[32], "HmacSha256"));
			fail();
		} catch (BadSAML2AssertionException e) {
			assertEquals("Missing XML signature", e.getMessage());
		}
	}
}

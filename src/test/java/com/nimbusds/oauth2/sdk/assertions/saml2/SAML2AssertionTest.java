package com.nimbusds.oauth2.sdk.assertions.saml2;


import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;

import junit.framework.TestCase;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.util.Pair;


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


	public void testCreateAndValidate()
		throws Exception {

		URI issuer = URI.create("https://saml.idp.com");
		String subjectFormat = NameIDType.EMAIL;
		int lifetime =5*60;
		BasicCredential credential = new BasicCredential();
		Pair<RSAPublicKey,RSAPrivateKey> keyPair = generateRSAKeyPair();
		credential.setPublicKey(keyPair.getFirst());
		credential.setPrivateKey(keyPair.getSecond());
		credential.setUsageType(UsageType.SIGNING);

		SAML2AssertionFactory f = new SAML2AssertionFactory(issuer.toString(), subjectFormat, lifetime, credential);

		assertEquals(issuer.toString(), f.getIssuer());
		assertEquals(subjectFormat, f.getSubjectFormat());
		assertEquals(lifetime, f.getAssertionLifetime());
		assertEquals(credential, f.getSigningCredential());

		String xml = f.createAssertionString(URI.create("https://c2id.com/token"), "alice@wonderland.net");

		assertFalse(xml.startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));

		// Parse back
		SAML2AssertionValidator v = new SAML2AssertionValidator(Collections.singletonList("https://c2id.com/token"));

		assertTrue(v.getExpectedAudience().contains("https://c2id.com/token"));
		assertEquals(1, v.getExpectedAudience().size());

		Assertion a = v.validate(xml, keyPair.getFirst());

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
	}
}
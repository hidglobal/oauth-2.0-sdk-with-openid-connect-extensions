package com.nimbusds.oauth2.sdk;


import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import junit.framework.TestCase;


/**
 * Tests the JWT bearer grant.
 */
public class JWTBearerGrantTest extends TestCase {


	public void testRejectUnsignedAssertion() {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.build();

		try {
			new JWTBearerGrant(new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet));
		} catch (IllegalArgumentException e) {
			assertEquals("The JWT assertion must not be in a unsigned state", e.getMessage());
		}
	}


	public void testRejectUnencryptedAssertion() {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.build();

		try {
			new JWTBearerGrant(new EncryptedJWT(new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128CBC_HS256), claimsSet));
		} catch (IllegalArgumentException e) {
			assertEquals("The JWT assertion must not be in a unencrypted state", e.getMessage());
		}
	}


	public void testSignedJWTConstructorAndParser()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.build();

		SignedJWT assertion = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

		assertion.sign(new MACSigner(new Secret().getValueBytes()));

		JWTBearerGrant grant = new JWTBearerGrant(assertion);

		assertEquals(GrantType.JWT_BEARER, grant.getType());
		assertEquals(assertion, grant.getJWTAssertion());
		assertEquals(assertion.serialize(), grant.getAssertion());

		Map<String,String> params = grant.toParameters();
		assertEquals(GrantType.JWT_BEARER.getValue(), params.get("grant_type"));
		assertEquals(assertion.serialize(), params.get("assertion"));
		assertEquals(2, params.size());

		grant = JWTBearerGrant.parse(params);
		assertEquals(GrantType.JWT_BEARER, grant.getType());
		assertTrue(grant.getJWTAssertion() instanceof SignedJWT);
		assertEquals(assertion.serialize(), grant.getAssertion());
	}


	public void testEncryptedJWTConstructorAndParser()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.build();

		EncryptedJWT assertion = new EncryptedJWT(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256), claimsSet);

		byte secret[] = new byte[32];
		new SecureRandom().nextBytes(secret);

		assertion.encrypt(new DirectEncrypter(secret));

		JWTBearerGrant grant = new JWTBearerGrant(assertion);

		assertEquals(GrantType.JWT_BEARER, grant.getType());
		assertEquals(assertion, grant.getJWTAssertion());
		assertEquals(assertion.serialize(), grant.getAssertion());

		Map<String,String> params = grant.toParameters();
		assertEquals(GrantType.JWT_BEARER.getValue(), params.get("grant_type"));
		assertEquals(assertion.serialize(), params.get("assertion"));
		assertEquals(2, params.size());

		grant = JWTBearerGrant.parse(params);
		assertEquals(GrantType.JWT_BEARER, grant.getType());
		assertTrue(grant.getJWTAssertion() instanceof EncryptedJWT);
		assertEquals(assertion.serialize(), grant.getAssertion());
	}


	public void testParseInvalidGrantType()
		throws JOSEException {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.build();

		SignedJWT assertion = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
		assertion.sign(new MACSigner(new Secret().getValueBytes()));

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", "invalid-grant");
		params.put("assertion", assertion.serialize());

		try {
			JWTBearerGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.UNSUPPORTED_GRANT_TYPE, e.getErrorObject());
		}
	}


	public void testParseMissingAssertion() {

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", GrantType.JWT_BEARER.getValue());

		try {
			JWTBearerGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
		}
	}


	public void testParseInvalidJWTAssertion() {

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", GrantType.JWT_BEARER.getValue());
		params.put("assertion", "invalid-jwt");

		try {
			JWTBearerGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
		}
	}


	public void testParseRejectPlainJWT() {

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", GrantType.JWT_BEARER.getValue());
		params.put("assertion", new PlainJWT(new JWTClaimsSet.Builder().subject("alice").build()).serialize());

		try {
			JWTBearerGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
		}
	}


	public void testEncryptedJWT()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.build();

		JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM);

		EncryptedJWT jwt = new EncryptedJWT(header, claimsSet);

		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey key = keyGen.generateKey();

		DirectEncrypter encrypter = new DirectEncrypter(key);
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jwt.encrypt(encrypter);

		JWTBearerGrant jwtBearerGrant = new JWTBearerGrant(jwt);

		Map<String,String> params = jwtBearerGrant.toParameters();

		jwtBearerGrant = JWTBearerGrant.parse(params);

		jwt = (EncryptedJWT)jwtBearerGrant.getJWTAssertion();
		assertNotNull(jwt);

		DirectDecrypter decrypter = new DirectDecrypter(key);
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jwt.decrypt(decrypter);
		assertEquals("alice", jwt.getJWTClaimsSet().getSubject());
	}


	public void testEncryptedJWT_asJOSEObject()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.build();

		JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM);

		EncryptedJWT jwt = new EncryptedJWT(header, claimsSet);

		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey key = keyGen.generateKey();

		DirectEncrypter encrypter = new DirectEncrypter(key);
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jwt.encrypt(encrypter);

		JWTBearerGrant jwtBearerGrant = new JWTBearerGrant(jwt);

		Map<String,String> params = jwtBearerGrant.toParameters();

		jwtBearerGrant = JWTBearerGrant.parse(params);

		jwt = (EncryptedJWT)jwtBearerGrant.getJOSEAssertion();
		assertNotNull(jwt);

		DirectDecrypter decrypter = new DirectDecrypter(key);
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jwt.decrypt(decrypter);
		assertEquals("alice", jwt.getJWTClaimsSet().getSubject());
	}


	public void testNestedJWT()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.subject("alice")
				.build();

		// Sign
		JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS256);
		SignedJWT jwt = new SignedJWT(jwsHeader, claimsSet);
		Secret secret = new Secret();
		jwt.sign(new MACSigner(secret.getValueBytes()));


		// Encrypt
		JWEHeader jweHeader = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128GCM)
				.contentType("JWT")
				.build();

		JWEObject jweObject = new JWEObject(jweHeader, new Payload(jwt));

		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey key = keyGen.generateKey();

		DirectEncrypter encrypter = new DirectEncrypter(key);
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.encrypt(encrypter);

		JWTBearerGrant jwtBearerGrant = new JWTBearerGrant(jweObject);

		Map<String,String> params = jwtBearerGrant.toParameters();

		jwtBearerGrant = JWTBearerGrant.parse(params);

		assertNull(jwtBearerGrant.getJWTAssertion());

		jweObject = (JWEObject)jwtBearerGrant.getJOSEAssertion();

		DirectDecrypter decrypter = new DirectDecrypter(key);
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.decrypt(decrypter);

		jwt = jweObject.getPayload().toSignedJWT();

		assertTrue(jwt.verify(new MACVerifier(secret.getValueBytes())));

		assertEquals("alice", jwt.getJWTClaimsSet().getSubject());
	}


	public void testNestedJWT_ctyLowerCase()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.subject("alice")
				.build();

		// Sign
		JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS256);
		SignedJWT jwt = new SignedJWT(jwsHeader, claimsSet);
		Secret secret = new Secret();
		jwt.sign(new MACSigner(secret.getValueBytes()));


		// Encrypt
		JWEHeader jweHeader = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128GCM)
				.contentType("jwt")
				.build();

		JWEObject jweObject = new JWEObject(jweHeader, new Payload(jwt));

		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey key = keyGen.generateKey();

		DirectEncrypter encrypter = new DirectEncrypter(key);
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.encrypt(encrypter);

		JWTBearerGrant jwtBearerGrant = new JWTBearerGrant(jweObject);

		Map<String,String> params = jwtBearerGrant.toParameters();

		jwtBearerGrant = JWTBearerGrant.parse(params);

		assertNull(jwtBearerGrant.getJWTAssertion());

		jweObject = (JWEObject)jwtBearerGrant.getJOSEAssertion();

		DirectDecrypter decrypter = new DirectDecrypter(key);
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.decrypt(decrypter);

		jwt = jweObject.getPayload().toSignedJWT();

		assertTrue(jwt.verify(new MACVerifier(secret.getValueBytes())));

		assertEquals("alice", jwt.getJWTClaimsSet().getSubject());
	}
}

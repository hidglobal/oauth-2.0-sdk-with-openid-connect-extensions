package com.nimbusds.openid.connect.sdk.validators;


import java.net.URI;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.BadJWEException;
import com.nimbusds.jose.proc.BadJWSException;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.jose.jwk.ImmutableJWKSet;
import com.nimbusds.oauth2.sdk.jose.jwk.JWEDecryptionKeySelector;
import com.nimbusds.oauth2.sdk.jose.jwk.JWSVerificationKeySelector;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import junit.framework.TestCase;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;


/**
 * Tests the ID token verifier.
 */
public class IDTokenValidatorTest extends TestCase {


	public void testConstant() {

		assertEquals(60, IDTokenValidator.DEFAULT_MAX_CLOCK_SKEW);
	}


	public void testVerifyPlain()
		throws Exception {

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Date now = new Date();

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.issuer(iss.getValue())
				.subject("alice")
				.audience(clientID.getValue())
				.expirationTime(new Date(now.getTime() + 10*60*1000L))
				.issueTime(now)
				.build();

		PlainJWT idToken = new PlainJWT(claimsSet);

		IDTokenValidator idTokenValidator = new IDTokenValidator(iss, clientID);
		assertEquals(iss, idTokenValidator.getExpectedIssuer());
		assertEquals(clientID, idTokenValidator.getClientID());
		assertNull(idTokenValidator.getJWSKeySelector());
		assertNull(idTokenValidator.getJWEKeySelector());

		IDTokenClaimsSet idTokenClaimsSet = idTokenValidator.validate(idToken, null);
		assertEquals(iss, idTokenClaimsSet.getIssuer());
		assertEquals(new Subject("alice"), idTokenClaimsSet.getSubject());
		assertTrue(idTokenClaimsSet.getAudience().contains(new Audience("123")));
		assertNotNull(idTokenClaimsSet.getExpirationTime());
		assertNotNull(idTokenClaimsSet.getIssueTime());
	}


	public void testVerifyPlainExpired()
		throws Exception {

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Date now = new Date();

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.issuer(iss.getValue())
				.subject("alice")
				.audience(clientID.getValue())
				.expirationTime(new Date(now.getTime() - 5*60*1000L))
				.issueTime(new Date(now.getTime() - 10*60*1000L))
				.build();

		PlainJWT idToken = new PlainJWT(claimsSet);

		IDTokenValidator idTokenValidator = new IDTokenValidator(iss, clientID);

		try {
			idTokenValidator.validate(idToken, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Expired JWT", e.getMessage());
		}
	}


	public void testVerifySigned()
		throws Exception {

		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(1024);
		KeyPair keyPair = gen.generateKeyPair();
		RSAKey rsaJWK = new RSAKey.Builder((RSAPublicKey)keyPair.getPublic())
				.privateKey((RSAPrivateKey)keyPair.getPrivate())
				.keyID("1")
				.keyUse(KeyUse.SIGNATURE)
				.build();
		JWKSet jwkSet = new JWKSet(rsaJWK);

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Date now = new Date();

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.issuer(iss.getValue())
				.subject("alice")
				.audience(clientID.getValue())
				.expirationTime(new Date(now.getTime() + 10*60*1000L))
				.issueTime(now)
				.build();

		SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
		idToken.sign(new RSASSASigner(rsaJWK));

		IDTokenValidator idTokenValidator = new IDTokenValidator(iss, clientID, JWSAlgorithm.RS256, jwkSet);
		assertNotNull(idTokenValidator.getJWSKeySelector());
		assertNull(idTokenValidator.getJWEKeySelector());

		IDTokenClaimsSet idTokenClaimsSet = idTokenValidator.validate(idToken, null);
		assertEquals(iss, idTokenClaimsSet.getIssuer());
		assertEquals(new Subject("alice"), idTokenClaimsSet.getSubject());
		assertTrue(idTokenClaimsSet.getAudience().contains(new Audience("123")));
		assertNotNull(idTokenClaimsSet.getExpirationTime());
		assertNotNull(idTokenClaimsSet.getIssueTime());
	}


	public void testVerifyBadSigned()
		throws Exception {

		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(1024);
		KeyPair keyPair = gen.generateKeyPair();
		RSAKey rsaJWK = new RSAKey.Builder((RSAPublicKey)keyPair.getPublic())
				.privateKey((RSAPrivateKey)keyPair.getPrivate())
				.keyID("1")
				.keyUse(KeyUse.SIGNATURE)
				.build();
		JWKSet jwkSet = new JWKSet(rsaJWK);

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Date now = new Date();

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.issuer(iss.getValue())
				.subject("alice")
				.audience(clientID.getValue())
				.expirationTime(new Date(now.getTime() + 10*60*1000L))
				.issueTime(now)
				.build();

		SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
		idToken.sign(new RSASSASigner(rsaJWK));
		idToken = new SignedJWT(idToken.getHeader().toBase64URL(), idToken.getPayload().toBase64URL(), Base64URL.encode("bad-sig"));

		IDTokenValidator idTokenValidator = new IDTokenValidator(iss, clientID, JWSAlgorithm.RS256, jwkSet);

		try {
			idTokenValidator.validate(idToken, null);
			fail();
		} catch (BadJWSException e) {
			assertEquals("Signed JWT rejected: Invalid signature", e.getMessage());
		}
	}


	public void testVerifySignedWithNonce()
		throws Exception {

		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(1024);
		KeyPair keyPair = gen.generateKeyPair();
		RSAKey rsaJWK = new RSAKey.Builder((RSAPublicKey)keyPair.getPublic())
				.privateKey((RSAPrivateKey)keyPair.getPrivate())
				.keyID("1")
				.keyUse(KeyUse.SIGNATURE)
				.build();
		JWKSet jwkSet = new JWKSet(rsaJWK);

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Date now = new Date();

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.issuer(iss.getValue())
				.subject("alice")
				.audience(clientID.getValue())
				.expirationTime(new Date(now.getTime() + 10*60*1000L))
				.issueTime(now)
				.claim("nonce", "xyz")
				.build();

		SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
		idToken.sign(new RSASSASigner(rsaJWK));

		IDTokenValidator idTokenValidator = new IDTokenValidator(iss, clientID, JWSAlgorithm.RS256, jwkSet);
		assertNotNull(idTokenValidator.getJWSKeySelector());
		assertNull(idTokenValidator.getJWEKeySelector());

		IDTokenClaimsSet idTokenClaimsSet = idTokenValidator.validate(idToken, new Nonce("xyz"));
		assertEquals(iss, idTokenClaimsSet.getIssuer());
		assertEquals(new Subject("alice"), idTokenClaimsSet.getSubject());
		assertTrue(idTokenClaimsSet.getAudience().contains(new Audience("123")));
		assertNotNull(idTokenClaimsSet.getExpirationTime());
		assertNotNull(idTokenClaimsSet.getIssueTime());
		assertEquals(new Nonce("xyz"), idTokenClaimsSet.getNonce());
	}


	public void testVerifyHmacWithNonce()
		throws Exception {

		Secret clientSecret = new Secret(ByteUtils.byteLength(256));

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Date now = new Date();

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.issuer(iss.getValue())
				.subject("alice")
				.audience(clientID.getValue())
				.expirationTime(new Date(now.getTime() + 10*60*1000L))
				.issueTime(now)
				.claim("nonce", "xyz")
				.build();

		SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
		idToken.sign(new MACSigner(clientSecret.getValueBytes()));

		IDTokenValidator idTokenValidator = new IDTokenValidator(iss, clientID, JWSAlgorithm.HS256, clientSecret);
		assertNotNull(idTokenValidator.getJWSKeySelector());
		assertNull(idTokenValidator.getJWEKeySelector());

		IDTokenClaimsSet idTokenClaimsSet = idTokenValidator.validate(idToken, new Nonce("xyz"));
		assertEquals(iss, idTokenClaimsSet.getIssuer());
		assertEquals(new Subject("alice"), idTokenClaimsSet.getSubject());
		assertTrue(idTokenClaimsSet.getAudience().contains(new Audience("123")));
		assertNotNull(idTokenClaimsSet.getExpirationTime());
		assertNotNull(idTokenClaimsSet.getIssueTime());
		assertEquals(new Nonce("xyz"), idTokenClaimsSet.getNonce());
	}


	public void testVerifyHmacWithoutNonce()
		throws Exception {

		Secret clientSecret = new Secret(ByteUtils.byteLength(256));

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Date now = new Date();

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.issuer(iss.getValue())
				.subject("alice")
				.audience(clientID.getValue())
				.expirationTime(new Date(now.getTime() + 10*60*1000L))
				.issueTime(now)
				.build();

		SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
		idToken.sign(new MACSigner(clientSecret.getValueBytes()));

		IDTokenValidator idTokenValidator = new IDTokenValidator(iss, clientID, JWSAlgorithm.HS256, clientSecret);
		assertNotNull(idTokenValidator.getJWSKeySelector());
		assertNull(idTokenValidator.getJWEKeySelector());

		IDTokenClaimsSet idTokenClaimsSet = idTokenValidator.validate(idToken, null);
		assertEquals(iss, idTokenClaimsSet.getIssuer());
		assertEquals(new Subject("alice"), idTokenClaimsSet.getSubject());
		assertTrue(idTokenClaimsSet.getAudience().contains(new Audience("123")));
		assertNotNull(idTokenClaimsSet.getExpirationTime());
		assertNotNull(idTokenClaimsSet.getIssueTime());
		assertNull(idTokenClaimsSet.getNonce());
	}


	public void testVerifyBadHmac()
		throws Exception {

		Secret clientSecret = new Secret(ByteUtils.byteLength(256));

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Date now = new Date();

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.issuer(iss.getValue())
				.subject("alice")
				.audience(clientID.getValue())
				.expirationTime(new Date(now.getTime() + 10*60*1000L))
				.issueTime(now)
				.build();

		SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
		idToken.sign(new MACSigner(new Secret(ByteUtils.byteLength(256)).getValueBytes()));

		IDTokenValidator idTokenValidator = new IDTokenValidator(iss, clientID, JWSAlgorithm.HS256, clientSecret);

		try {
			idTokenValidator.validate(idToken, null);
			fail();
		} catch (BadJWSException e) {
			assertEquals("Signed JWT rejected: Invalid signature", e.getMessage());
		}
	}


	public void testVerifyNested()
		throws Exception {

		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(1024);

		// Generate OP key
		KeyPair keyPair = gen.generateKeyPair();
		RSAKey opJWK = new RSAKey.Builder((RSAPublicKey)keyPair.getPublic())
				.privateKey((RSAPrivateKey)keyPair.getPrivate())
				.keyID("s1")
				.keyUse(KeyUse.SIGNATURE)
				.build();
		final JWKSet opJWKSet = new JWKSet(opJWK);

		// Generate RP key
		keyPair = gen.generateKeyPair();
		RSAKey rpJWK = new RSAKey.Builder((RSAPublicKey)keyPair.getPublic())
				.privateKey((RSAPrivateKey)keyPair.getPrivate())
				.keyID("e1")
				.keyUse(KeyUse.ENCRYPTION)
				.build();
		final JWKSet rpJWKSet = new JWKSet(rpJWK);

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Date now = new Date();

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.issuer(iss.getValue())
				.subject("alice")
				.audience(clientID.getValue())
				.expirationTime(new Date(now.getTime() + 10*60*1000L))
				.issueTime(now)
				.build();

		SignedJWT idToken = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("s1").build(), claimsSet);
		idToken.sign(new RSASSASigner(opJWK));

		JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256).keyID("e1").contentType("JWT").build(), new Payload(idToken));
		jweObject.encrypt(new RSAEncrypter(rpJWK));

		String idTokenString = jweObject.serialize();

		IDTokenValidator verifier = new IDTokenValidator(iss, clientID,
				new JWSVerificationKeySelector(
						iss,
						JWSAlgorithm.RS256,
						new ImmutableJWKSet(iss, opJWKSet)),
				new JWEDecryptionKeySelector(
						clientID,
						JWEAlgorithm.RSA1_5,
						EncryptionMethod.A128CBC_HS256,
						new ImmutableJWKSet(clientID, rpJWKSet)));

		assertEquals(iss, verifier.getExpectedIssuer());
		assertEquals(clientID, verifier.getClientID());
		assertNotNull(verifier.getJWSKeySelector());
		assertNotNull(verifier.getJWEKeySelector());

		IDTokenClaimsSet idTokenClaimsSet = verifier.validate(JWTParser.parse(idTokenString), null);

		assertEquals(iss, idTokenClaimsSet.getIssuer());
		assertEquals(new Subject("alice"), idTokenClaimsSet.getSubject());
		assertTrue(idTokenClaimsSet.getAudience().contains(new Audience("123")));
		assertNotNull(idTokenClaimsSet.getExpirationTime());
		assertNotNull(idTokenClaimsSet.getIssueTime());
	}


	public void testBadEncryption()
		throws Exception {

		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(1024);

		// Generate OP key
		KeyPair keyPair = gen.generateKeyPair();
		RSAKey opJWK = new RSAKey.Builder((RSAPublicKey)keyPair.getPublic())
				.privateKey((RSAPrivateKey)keyPair.getPrivate())
				.keyID("s1")
				.keyUse(KeyUse.SIGNATURE)
				.build();
		final JWKSet opJWKSet = new JWKSet(opJWK);

		// Generate RP key
		keyPair = gen.generateKeyPair();
		RSAKey rpJWK = new RSAKey.Builder((RSAPublicKey)keyPair.getPublic())
				.privateKey((RSAPrivateKey)keyPair.getPrivate())
				.keyID("e1")
				.keyUse(KeyUse.ENCRYPTION)
				.build();
		final JWKSet rpJWKSet = new JWKSet(rpJWK);


		// Generate bad encryption key
		keyPair = gen.generateKeyPair();
		RSAKey badJWK = new RSAKey.Builder((RSAPublicKey)keyPair.getPublic())
				.privateKey((RSAPrivateKey)keyPair.getPrivate())
				.keyID("e1")
				.keyUse(KeyUse.ENCRYPTION)
				.build();
		final JWKSet badJWKSet = new JWKSet(rpJWK);

		Issuer iss = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Date now = new Date();

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.issuer(iss.getValue())
				.subject("alice")
				.audience(clientID.getValue())
				.expirationTime(new Date(now.getTime() + 10*60*1000L))
				.issueTime(now)
				.build();

		SignedJWT idToken = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("s1").build(), claimsSet);
		idToken.sign(new RSASSASigner(opJWK));

		JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256).keyID("e1").contentType("JWT").build(), new Payload(idToken));
		jweObject.encrypt(new RSAEncrypter(badJWK));

		String idTokenString = jweObject.serialize();

		IDTokenValidator verifier = new IDTokenValidator(iss, clientID,
				new JWSVerificationKeySelector(
						iss,
						JWSAlgorithm.RS256,
						new ImmutableJWKSet(iss, opJWKSet)),
				new JWEDecryptionKeySelector(
						clientID,
						JWEAlgorithm.RSA1_5,
						EncryptionMethod.A128CBC_HS256,
						new ImmutableJWKSet(clientID, rpJWKSet)));

		try {
			verifier.validate(JWTParser.parse(idTokenString), null);
			fail();
		} catch (BadJWEException e) {
			assertEquals("Encrypted JWT rejected: Given final block not properly padded", e.getMessage());
		}
	}


	public void testGetSetClockSkew() {

		IDTokenValidator verifier = new IDTokenValidator(new Issuer("https://c2id.com"), new ClientID("123"));
		assertEquals(IDTokenValidator.DEFAULT_MAX_CLOCK_SKEW, verifier.getMaxClockSkew());
		verifier.setMaxClockSkew(30);
		assertEquals(30, verifier.getMaxClockSkew());
	}


	private Pair<OIDCProviderMetadata,List<RSAKey>> createOPMetadata()
		throws Exception {

		// Generate 2 RSA keys for the OP
		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(1024);
		KeyPair keyPair = pairGen.generateKeyPair();

		final RSAKey rsaJWK1 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("1")
			.build();

		keyPair = pairGen.generateKeyPair();

		final RSAKey rsaJWK2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("2")
			.build();

		OIDCProviderMetadata opMetadata = new OIDCProviderMetadata(
			new Issuer("https://c2id.com"),
			Collections.singletonList(SubjectType.PUBLIC),
			URI.create("https://c2id.com/jwks.json"));

		opMetadata.setIDTokenJWSAlgs(Arrays.asList(JWSAlgorithm.RS256, JWSAlgorithm.HS256));
		opMetadata.setIDTokenJWEAlgs(Collections.singletonList(JWEAlgorithm.RSA1_5));
		opMetadata.setIDTokenJWEEncs(Arrays.asList(EncryptionMethod.A128CBC_HS256, EncryptionMethod.A128GCM));
		opMetadata.setTokenEndpointAuthMethods(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
		opMetadata.applyDefaults();

		return new ImmutablePair<>(opMetadata, Arrays.asList(rsaJWK1, rsaJWK2));
	}


	public void testStaticFactoryMethod_HS256()
		throws Exception {

		// Create OP metadata
		OIDCProviderMetadata opMetadata = createOPMetadata().getLeft();

		// Create client registration
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setRedirectionURI(URI.create("https://example.com/cb"));
		metadata.setIDTokenJWSAlg(JWSAlgorithm.HS256);
		metadata.applyDefaults();

		OIDCClientInformation clientInfo = new OIDCClientInformation(new ClientID("123"), new Date(), metadata, new Secret(ByteUtils.byteLength(256)));

		// Create validator
		IDTokenValidator v = IDTokenValidator.create(opMetadata, clientInfo, null);
		assertEquals(opMetadata.getIssuer(), v.getExpectedIssuer());
		assertEquals(clientInfo.getID(), v.getClientID());
		assertNotNull(v.getJWSKeySelector());
		assertNull(v.getJWEKeySelector());

		// Check JWS key selector
		List<Key> matches = v.getJWSKeySelector().selectJWSKeys(new JWSHeader(JWSAlgorithm.HS256), null);
		assertEquals(1, matches.size());
		assertTrue(ArrayUtils.isEquals(clientInfo.getSecret().getValueBytes(), matches.get(0).getEncoded()));

		matches = v.getJWSKeySelector().selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("xxx").build(), null);
		assertTrue(matches.isEmpty());


		// Create ID token
		final Date now = new Date();
		final Date inOneHour = new Date(now.getTime() + 3600*1000L);
		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
			opMetadata.getIssuer(),
			new Subject("alice"),
			new Audience(clientInfo.getID()).toSingleAudienceList(),
			inOneHour, // exp
			now); // iat

		SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet.toJWTClaimsSet());
		idToken.sign(new MACSigner(clientInfo.getSecret().getValueBytes()));
		idToken = SignedJWT.parse(idToken.serialize());

		assertEquals(1, v.getJWSKeySelector().selectJWSKeys(idToken.getHeader(), null).size());

		// Validate
		IDTokenClaimsSet validated = v.validate(idToken, null);
		assertEquals(claimsSet.getIssuer(), validated.getIssuer());
		assertEquals(claimsSet.getSubject(), validated.getSubject());
		assertEquals(claimsSet.getAudience().get(0), validated.getAudience().get(0));
		assertEquals(1, validated.getAudience().size());
		assertEquals(claimsSet.getExpirationTime(), validated.getExpirationTime());
		assertEquals(claimsSet.getIssueTime(), validated.getIssueTime());

		// Sign ID token with invalid RSA key
		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(1024);
		KeyPair keyPair = pairGen.generateKeyPair();

		final RSAKey badKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("1")
			.build();

		idToken = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(badKey.getKeyID()).build(), claimsSet.toJWTClaimsSet());
		idToken.sign(new RSASSASigner(badKey));
		assertEquals(JWSObject.State.SIGNED, idToken.getState());

		try {
			v.validate(idToken, null);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Signed JWT rejected: No matching key(s) found", e.getMessage());
		}

		// Sign ID token with bad HMAC key
		idToken = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("XXXXXXX").build(), claimsSet.toJWTClaimsSet());
		idToken.sign(new MACSigner("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
		assertEquals(JWSObject.State.SIGNED, idToken.getState());

		try {
			v.validate(idToken, null);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Signed JWT rejected: No matching key(s) found", e.getMessage());
		}
	}
}

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

import static net.jadler.Jadler.*;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.BadJWSException;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.jose.jwk.ImmutableJWKSet;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import junit.framework.TestCase;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.After;
import org.junit.Before;


/**
 * Tests the static factory method with HTTP retrieval of remote OP JWK set to
 * complete ID token validation.
 */
public class IDTokenValidatorWithHTTPTest extends TestCase {
	
	@Before
	public void setUp() {
		initJadler();
	}


	@After
	public void tearDown() {
		closeJadler();
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
			URI.create("http://localhost:" + port() + "/jwks.json"));

		opMetadata.setIDTokenJWSAlgs(Arrays.asList(JWSAlgorithm.RS256, JWSAlgorithm.HS256));
		opMetadata.setIDTokenJWEAlgs(Collections.singletonList(JWEAlgorithm.RSA1_5));
		opMetadata.setIDTokenJWEEncs(Arrays.asList(EncryptionMethod.A128CBC_HS256, EncryptionMethod.A128GCM));
		opMetadata.setTokenEndpointAuthMethods(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
		opMetadata.applyDefaults();

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/jwks.json")
			.respond()
			.withStatus(200)
			.withHeader("Content-Type", "application/json")
			.withBody(new JWKSet(Arrays.asList((JWK)rsaJWK1, (JWK)rsaJWK2)).toJSONObject().toJSONString());

		return new ImmutablePair<>(opMetadata, Arrays.asList(rsaJWK1, rsaJWK2));
	}


	public void testStaticFactoryMethod_RS256()
		throws Exception {

		// Create OP metadata
		Pair<OIDCProviderMetadata,List<RSAKey>> opInfo = createOPMetadata();
		OIDCProviderMetadata opMetadata = opInfo.getLeft();
		RSAKey rsaKey1 = opInfo.getRight().get(0);
		RSAKey rsaKey2 = opInfo.getRight().get(1);

		// Create client registration
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setRedirectionURI(URI.create("https://example.com/cb"));
		metadata.applyDefaults();

		OIDCClientInformation clientInfo = new OIDCClientInformation(new ClientID("123"), new Date(), metadata, new Secret());

		// Create validator
		IDTokenValidator v = IDTokenValidator.create(opMetadata, clientInfo, null);
		assertEquals(opMetadata.getIssuer(), v.getExpectedIssuer());
		assertEquals(clientInfo.getID(), v.getClientID());
		assertNotNull(v.getJWSKeySelector());
		assertNull(v.getJWEKeySelector());

		// Check JWS key selector
		List<Key> matches = v.getJWSKeySelector().selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey1.getKeyID()).build(), null);
		assertEquals(1, matches.size());
		matches = v.getJWSKeySelector().selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey2.getKeyID()).build(), null);
		assertEquals(1, matches.size());
		matches = v.getJWSKeySelector().selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), null);
		assertEquals(2, matches.size());


		// Create ID token
		final Date now = new Date();
		final Date inOneHour = new Date(now.getTime() + 3600*1000L);
		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
			opMetadata.getIssuer(),
			new Subject("alice"),
			new Audience(clientInfo.getID()).toSingleAudienceList(),
			inOneHour, // exp
			now); // iat

		SignedJWT idToken = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey1.getKeyID()).build(), claimsSet.toJWTClaimsSet());
		idToken.sign(new RSASSASigner(rsaKey1));

		// Validate
		IDTokenClaimsSet validated = v.validate(idToken, null);
		assertEquals(claimsSet.getIssuer(), validated.getIssuer());
		assertEquals(claimsSet.getSubject(), validated.getSubject());
		assertEquals(claimsSet.getAudience().get(0), validated.getAudience().get(0));
		assertEquals(1, validated.getAudience().size());
		assertEquals(claimsSet.getExpirationTime(), validated.getExpirationTime());
		assertEquals(claimsSet.getIssueTime(), validated.getIssueTime());

		// Create an ID token with unspecified key ID
		idToken = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), claimsSet.toJWTClaimsSet());
		idToken.sign(new RSASSASigner(rsaKey1));

		// Validate again
		validated = v.validate(idToken, null);
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

		idToken = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey1.getKeyID()).build(), claimsSet.toJWTClaimsSet());
		idToken.sign(new RSASSASigner(badKey));

		try {
			v.validate(idToken, null);
			fail();
		} catch (BadJWSException e) {
			assertEquals("Signed JWT rejected: Invalid signature", e.getMessage());
		}

		// Sign ID token with RSA key with unexpected key ID
		idToken = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("XXXXXXX").build(), claimsSet.toJWTClaimsSet());
		idToken.sign(new RSASSASigner(rsaKey1));

		try {
			v.validate(idToken, null);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Signed JWT rejected: No matching key(s) found", e.getMessage());
		}
	}


	public void testStaticFactoryMethod_nested_JWS_JWE()
		throws Exception {

		// Create OP metadata
		Pair<OIDCProviderMetadata,List<RSAKey>> opInfo = createOPMetadata();
		OIDCProviderMetadata opMetadata = opInfo.getLeft();
		RSAKey rsaKey1 = opInfo.getRight().get(0);
		RSAKey rsaKey2 = opInfo.getRight().get(1);

		// Create client registration
		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(1024);
		KeyPair clientKeyPair = pairGen.generateKeyPair();

		final RSAKey clientJWK = new RSAKey.Builder((RSAPublicKey) clientKeyPair.getPublic())
			.privateKey((RSAPrivateKey) clientKeyPair.getPrivate())
			.keyID("e1")
			.build();

		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setRedirectionURI(URI.create("https://example.com/cb"));
		metadata.setIDTokenJWSAlg(JWSAlgorithm.RS256);
		metadata.setIDTokenJWEAlg(JWEAlgorithm.RSA1_5);
		metadata.setIDTokenJWEEnc(EncryptionMethod.A128CBC_HS256);
		metadata.applyDefaults();

		OIDCClientInformation clientInfo = new OIDCClientInformation(new ClientID("123"), new Date(), metadata, new Secret());

		// Create validator
		IDTokenValidator v = IDTokenValidator.create(opMetadata, clientInfo, new ImmutableJWKSet(clientInfo.getID(), new JWKSet(clientJWK)));
		assertEquals(opMetadata.getIssuer(), v.getExpectedIssuer());
		assertEquals(clientInfo.getID(), v.getClientID());
		assertNotNull(v.getJWSKeySelector());
		assertNotNull(v.getJWEKeySelector());

		// Check JWS key selector
		List<Key> matches = v.getJWSKeySelector().selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey1.getKeyID()).build(), null);
		assertEquals(1, matches.size());
		matches = v.getJWSKeySelector().selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey2.getKeyID()).build(), null);
		assertEquals(1, matches.size());
		matches = v.getJWSKeySelector().selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), null);
		assertEquals(2, matches.size());

		// Check JWE key selector
		matches = v.getJWEKeySelector().selectJWEKeys(new JWEHeader.Builder(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256).keyID("e1").build(), null);
		assertEquals(1, matches.size());


		// Create ID token
		final Date now = new Date();
		final Date inOneHour = new Date(now.getTime() + 3600*1000L);
		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
			opMetadata.getIssuer(),
			new Subject("alice"),
			new Audience(clientInfo.getID()).toSingleAudienceList(),
			inOneHour, // exp
			now); // iat

		SignedJWT idToken = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey1.getKeyID()).build(), claimsSet.toJWTClaimsSet());
		idToken.sign(new RSASSASigner(rsaKey1));

		// Encrypt with client public RSA key
		JWEObject encrypted = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256).keyID("e1").build(), new Payload(idToken));
		encrypted.encrypt(new RSAEncrypter(clientJWK));

		// Validate
		IDTokenClaimsSet validated = v.validate(idToken, null);
		assertEquals(claimsSet.getIssuer(), validated.getIssuer());
		assertEquals(claimsSet.getSubject(), validated.getSubject());
		assertEquals(claimsSet.getAudience().get(0), validated.getAudience().get(0));
		assertEquals(1, validated.getAudience().size());
		assertEquals(claimsSet.getExpirationTime(), validated.getExpirationTime());
		assertEquals(claimsSet.getIssueTime(), validated.getIssueTime());

		// Create an ID token with unspecified key ID
		idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet.toJWTClaimsSet());
		idToken.sign(new RSASSASigner(rsaKey1));
		encrypted = new JWEObject(new JWEHeader(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256), new Payload(idToken));
		encrypted.encrypt(new RSAEncrypter(clientJWK));

		// Validate again
		validated = v.validate(idToken, null);
		assertEquals(claimsSet.getIssuer(), validated.getIssuer());
		assertEquals(claimsSet.getSubject(), validated.getSubject());
		assertEquals(claimsSet.getAudience().get(0), validated.getAudience().get(0));
		assertEquals(1, validated.getAudience().size());
		assertEquals(claimsSet.getExpirationTime(), validated.getExpirationTime());
		assertEquals(claimsSet.getIssueTime(), validated.getIssueTime());

		// Sign ID token with invalid RSA key
		KeyPair keyPair = pairGen.generateKeyPair();

		final RSAKey badKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("1")
			.build();

		idToken = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey1.getKeyID()).build(), claimsSet.toJWTClaimsSet());
		idToken.sign(new RSASSASigner(badKey));

		try {
			v.validate(idToken, null);
			fail();
		} catch (BadJWSException e) {
			assertEquals("Signed JWT rejected: Invalid signature", e.getMessage());
		}

		// Sign ID token with RSA key with unexpected key ID
		idToken = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("XXXXXXX").build(), claimsSet.toJWTClaimsSet());
		idToken.sign(new RSASSASigner(rsaKey1));

		try {
			v.validate(idToken, null);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Signed JWT rejected: No matching key(s) found", e.getMessage());
		}
	}
}

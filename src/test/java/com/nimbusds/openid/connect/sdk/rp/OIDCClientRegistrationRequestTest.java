package com.nimbusds.openid.connect.sdk.rp;


import java.net.URI;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.mail.internet.InternetAddress;

import junit.framework.TestCase;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import com.nimbusds.langtag.LangTag;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;

import com.nimbusds.openid.connect.sdk.SubjectType;



/**
 * Tests the OIDC client registration class.
 */
public class OIDCClientRegistrationRequestTest extends TestCase {
	
	
	public void testRoundtrip() throws Exception {
		
		URI uri = new URI("https://server.example.com/connect/register");
		
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		
		Set<URI> redirectURIs = new HashSet<>();
		redirectURIs.add(new URI("https://client.example.org/callback"));
		metadata.setRedirectionURIs(redirectURIs);
		
		metadata.setApplicationType(ApplicationType.NATIVE);
		
		metadata.setJWKSetURI(new URI("https://client.example.org/my_public_keys.jwks"));
		
		OIDCClientRegistrationRequest request = new OIDCClientRegistrationRequest(uri, metadata, null);
		
		assertEquals(uri, request.getEndpointURI());
		
		assertNull(request.getAccessToken());
		
		metadata = request.getOIDCClientMetadata();
		
		redirectURIs = metadata.getRedirectionURIs();
		assertTrue(redirectURIs.contains(new URI("https://client.example.org/callback")));
		assertEquals(1, redirectURIs.size());
		
		assertEquals(ApplicationType.NATIVE, metadata.getApplicationType());
		
		assertEquals(new URI("https://client.example.org/my_public_keys.jwks"), metadata.getJWKSetURI());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(CommonContentTypes.APPLICATION_JSON, httpRequest.getContentType());
		
		System.out.println(httpRequest.getQuery());
		
		request = OIDCClientRegistrationRequest.parse(httpRequest);
		
		assertEquals(uri, request.getEndpointURI());
		
		assertNull(request.getAccessToken());
		
		metadata = request.getOIDCClientMetadata();
		
		redirectURIs = metadata.getRedirectionURIs();
		assertTrue(redirectURIs.contains(new URI("https://client.example.org/callback")));
		assertEquals(1, redirectURIs.size());
		
		assertEquals(ApplicationType.NATIVE, metadata.getApplicationType());
		
		assertEquals(new URI("https://client.example.org/my_public_keys.jwks"), metadata.getJWKSetURI());
	}
		
	
	public void testParse() throws Exception {
		
		URI uri = new URI("https://server.example.com/connect/register");
		
		String json = "{"
			+ "   \"application_type\": \"web\","
			+ "   \"redirect_uris\":[\"https://client.example.org/callback\",\"https://client.example.org/callback2\"],"
			+ "   \"client_name\": \"My Example\","
			+ "   \"client_name#ja-Jpan-JP\":\"クライアント名\","
			+ "   \"logo_uri\": \"https://client.example.org/logo.png\","
			+ "   \"subject_type\": \"pairwise\","
			+ "   \"sector_identifier_uri\":\"https://other.example.net/file_of_redirect_uris.json\","
			+ "   \"token_endpoint_auth_method\": \"client_secret_basic\","
			+ "   \"jwks_uri\": \"https://client.example.org/my_public_keys.jwks\","
			+ "   \"userinfo_encrypted_response_alg\": \"RSA1_5\","
			+ "   \"userinfo_encrypted_response_enc\": \"A128CBC-HS256\","
			+ "   \"contacts\": [\"ve7jtb@example.org\", \"mary@example.org\"],"
			+ "   \"request_uris\":[\"https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA\"]"
			+ "  }";
		
		System.out.println(json);
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, uri.toURL());
		httpRequest.setAuthorization("Bearer eyJhbGciOiJSUzI1NiJ9.eyJ");
		httpRequest.setContentType(CommonContentTypes.APPLICATION_JSON);
		httpRequest.setQuery(json);
		
		OIDCClientRegistrationRequest req = OIDCClientRegistrationRequest.parse(httpRequest);
		
		assertEquals(uri, req.getEndpointURI());
		
		OIDCClientMetadata metadata = req.getOIDCClientMetadata();
		
		assertEquals(ApplicationType.WEB, metadata.getApplicationType());
		
		Set<URI> redirectURIs = metadata.getRedirectionURIs();
		assertTrue(redirectURIs.contains(new URI("https://client.example.org/callback")));
		assertTrue(redirectURIs.contains(new URI("https://client.example.org/callback2")));
		assertEquals(2, redirectURIs.size());
		
		assertEquals("My Example", metadata.getName());
		assertEquals("My Example", metadata.getName(null));
		assertEquals("クライアント名", metadata.getName(LangTag.parse("ja-Jpan-JP")));
		assertEquals(2, metadata.getNameEntries().size());
		
		assertEquals(new URI("https://client.example.org/logo.png"), metadata.getLogoURI());
		assertEquals(new URI("https://client.example.org/logo.png"), metadata.getLogoURI(null));
		assertEquals(1, metadata.getLogoURIEntries().size());
		
		assertEquals(SubjectType.PAIRWISE, metadata.getSubjectType());
		assertEquals(new URI("https://other.example.net/file_of_redirect_uris.json"), metadata.getSectorIDURI());
		
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, metadata.getTokenEndpointAuthMethod());
		
		assertEquals(new URI("https://client.example.org/my_public_keys.jwks"), metadata.getJWKSetURI());
		
		assertEquals(JWEAlgorithm.RSA1_5, metadata.getUserInfoJWEAlg());
		assertEquals(EncryptionMethod.A128CBC_HS256, metadata.getUserInfoJWEEnc());
		
		List<InternetAddress> contacts = metadata.getContacts();
		assertTrue(contacts.contains(new InternetAddress("ve7jtb@example.org")));
		assertTrue(contacts.contains(new InternetAddress("mary@example.org")));
		assertEquals(2, contacts.size());
		
		Set<URI> requestObjectURIs = metadata.getRequestObjectURIs();
		assertTrue(requestObjectURIs.contains(new URI("https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA")));
	}


	public void testSoftwareStatement()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setIssuer("https://c2id.com");

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
		jwt.sign(new MACSigner("01234567890123456789012345678901"));

		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setRedirectionURI(new URI("https://client.com/in"));
		metadata.setName("Test App");

		OIDCClientRegistrationRequest request = new OIDCClientRegistrationRequest(new URI("https://c2id.com/reg"), metadata, jwt, null);

		assertEquals(metadata, request.getClientMetadata());
		assertEquals(jwt, request.getSoftwareStatement());
		assertNull(request.getAccessToken());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = OIDCClientRegistrationRequest.parse(httpRequest);

		assertEquals("https://client.com/in", request.getClientMetadata().getRedirectionURIs().iterator().next().toString());
		assertEquals("Test App", request.getClientMetadata().getName());
		assertEquals(jwt.serialize(), request.getSoftwareStatement().getParsedString());
		assertTrue(request.getSoftwareStatement().verify(new MACVerifier("01234567890123456789012345678901")));
	}


	public void testRejectUnsignedSoftwareStatement()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setIssuer("https://c2id.com");

		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setRedirectionURI(new URI("https://client.com/in"));
		metadata.setName("Test App");

		try {
			new OIDCClientRegistrationRequest(
				new URI("https://c2id.com/reg"),
				metadata,
				new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet),
				null);

		} catch (IllegalArgumentException e) {

			// ok
			assertEquals("The software statement JWT must be signed", e.getMessage());
		}

	}


	public void testRejectSoftwareStatementWithoutIssuer()
		throws Exception {

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet());
		jwt.sign(new MACSigner("01234567890123456789012345678901"));

		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setRedirectionURI(new URI("https://client.com/in"));
		metadata.setName("Test App");

		try {
			new OIDCClientRegistrationRequest(
				new URI("https://c2id.com/reg"),
				metadata,
				jwt,
				null);

		} catch (IllegalArgumentException e) {

			// ok
			assertEquals("The software statement JWT must contain an 'iss' claim", e.getMessage());
		}
	}
}
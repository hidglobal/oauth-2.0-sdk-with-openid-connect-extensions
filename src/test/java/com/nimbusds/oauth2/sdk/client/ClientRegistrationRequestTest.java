package com.nimbusds.oauth2.sdk.client;


import java.net.URI;
import java.util.List;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


/**
 * Tests the client registration request class.
 */
public class ClientRegistrationRequestTest extends TestCase {


	@SuppressWarnings("unchecked")
	public void testSerializeAndParse()
		throws Exception {

		URI uri = new URI("https://c2id.com/client-reg");

		ClientMetadata metadata = new ClientMetadata();
		metadata.setName("My test app");
		metadata.setRedirectionURI(new URI("https://client.com/callback"));
		metadata.applyDefaults();

		BearerAccessToken accessToken = new BearerAccessToken();

		ClientRegistrationRequest request = new ClientRegistrationRequest(uri, metadata, accessToken);

		HTTPRequest httpRequest = request.toHTTPRequest();

		assertEquals(uri.toString(), httpRequest.getURL().toString());
		assertTrue(httpRequest.getContentType().toString().startsWith("application/json"));

		JSONObject jsonObject = httpRequest.getQueryAsJSONObject();

		System.out.println(jsonObject);

		List<String> stringList = (List<String>)jsonObject.get("redirect_uris");
		assertEquals(metadata.getRedirectionURIs().iterator().next().toString(), stringList.get(0));
		assertEquals(metadata.getName(), (String) jsonObject.get("client_name"));
		assertEquals("client_secret_basic", (String)jsonObject.get("token_endpoint_auth_method"));
		stringList = (List<String>)jsonObject.get("response_types");
		assertEquals("code", stringList.get(0));
		stringList = (List<String>)jsonObject.get("grant_types");
		assertEquals("authorization_code", stringList.get(0));

		request = ClientRegistrationRequest.parse(httpRequest);

		assertEquals(metadata.getName(), request.getClientMetadata().getName());
		assertEquals(metadata.getRedirectionURIs().iterator().next().toString(), request.getClientMetadata().getRedirectionURIs().iterator().next().toString());
		assertEquals(metadata.getTokenEndpointAuthMethod(), request.getClientMetadata().getTokenEndpointAuthMethod());
		assertEquals("code", request.getClientMetadata().getResponseTypes().iterator().next().toString());
		assertEquals("authorization_code", request.getClientMetadata().getGrantTypes().iterator().next().toString());
	}
	

	public void testParse()
		throws Exception {
		
		URI endpointURI = new URI("https://server.example.com/register/");
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, endpointURI.toURL());
		httpRequest.setContentType(CommonContentTypes.APPLICATION_JSON);
		
		String json = "{"
			+ "    \"redirect_uris\":[\"https://client.example.org/callback\","
			+ "       \"https://client.example.org/callback2\"],"
			+ "    \"client_name\":\"My Example Client\","
			+ "    \"client_name#ja-Jpan-JP\":\"\\u30AF\\u30E9\\u30A4\\u30A2\\u30F3\\u30C8\\u540D\","
			+ "    \"token_endpoint_auth_method\":\"client_secret_basic\","
			+ "    \"scope\":\"read write dolphin\","
			+ "    \"logo_uri\":\"https://client.example.org/logo.png\","
			+ "    \"jwks_uri\":\"https://client.example.org/my_public_keys.jwks\""
			+ "   }";
		
		
		httpRequest.setQuery(json);
		
		ClientRegistrationRequest request = ClientRegistrationRequest.parse(httpRequest);
		
		assertNull(request.getAccessToken());
		
		ClientMetadata metadata = request.getClientMetadata();
		
		Set<URI> redirectURIs = metadata.getRedirectionURIs();
		assertTrue(redirectURIs.contains(new URI("https://client.example.org/callback")));
		assertTrue(redirectURIs.contains(new URI("https://client.example.org/callback2")));
		assertEquals(2, redirectURIs.size());
		
		assertEquals("My Example Client", metadata.getName());
		assertEquals("\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D", metadata.getName(LangTag.parse("ja-Jpan-JP")));
		
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, metadata.getTokenEndpointAuthMethod());
		
		assertEquals(Scope.parse("read write dolphin"), metadata.getScope());
		
		assertEquals(new URI("https://client.example.org/logo.png"), metadata.getLogoURI());
		
		assertEquals(new URI("https://client.example.org/my_public_keys.jwks"), metadata.getJWKSetURI());
	}


	public void testSoftwareStatement()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setIssuer("https://c2id.com");

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
		jwt.sign(new MACSigner("abcdef1234567890"));

		ClientMetadata metadata = new ClientMetadata();
		metadata.setRedirectionURI(new URI("https://client.com/in"));
		metadata.setName("Test App");

		ClientRegistrationRequest request = new ClientRegistrationRequest(new URI("https://c2id.com/reg"), metadata, jwt, null);

		assertEquals(metadata, request.getClientMetadata());
		assertEquals(jwt, request.getSoftwareStatement());
		assertNull(request.getAccessToken());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = ClientRegistrationRequest.parse(httpRequest);

		assertEquals("https://client.com/in", request.getClientMetadata().getRedirectionURIs().iterator().next().toString());
		assertEquals("Test App", request.getClientMetadata().getName());
		assertEquals(jwt.serialize(), request.getSoftwareStatement().getParsedString());
		assertTrue(request.getSoftwareStatement().verify(new MACVerifier("abcdef1234567890")));
	}


	public void testRejectUnsignedSoftwareStatement()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setIssuer("https://c2id.com");

		ClientMetadata metadata = new ClientMetadata();
		metadata.setRedirectionURI(new URI("https://client.com/in"));
		metadata.setName("Test App");

		try {
			new ClientRegistrationRequest(
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
		jwt.sign(new MACSigner("abcdef1234567890"));

		ClientMetadata metadata = new ClientMetadata();
		metadata.setRedirectionURI(new URI("https://client.com/in"));
		metadata.setName("Test App");

		try {
			new ClientRegistrationRequest(
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
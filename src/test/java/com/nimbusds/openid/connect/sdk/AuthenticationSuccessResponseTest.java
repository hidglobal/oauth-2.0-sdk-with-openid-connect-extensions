package com.nimbusds.openid.connect.sdk;


import java.net.URI;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Tests the authentication success response class.
 */
public class AuthenticationSuccessResponseTest extends TestCase {


	private static URI REDIRECT_URI;

	static {

		try {
			REDIRECT_URI = new URI("https://client.com/cb");

		} catch (Exception e) {
			// ignore
		}
	}


	public void testIDTokenResponse()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer("https://c2id.com")
			.audience(Arrays.asList("https://client.com"))
			.subject("alice")
			.issueTime(new Date(10000l))
			.expirationTime(new Date(20000l))
			.claim("nonce", "123")
			.build();

		SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

		idToken.sign(new MACSigner("01234567890123456789012345678901"));

		AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(
			REDIRECT_URI, null, idToken, null, new State("abc"), null, ResponseMode.FRAGMENT);

		assertTrue(response.indicatesSuccess());
		assertEquals(REDIRECT_URI, response.getRedirectionURI());
		assertEquals(idToken, response.getIDToken());
		assertNull(response.getAuthorizationCode());
		assertNull(response.getAccessToken());
		assertEquals("abc", response.getState().getValue());
		assertNull(response.getSessionState());

		assertTrue(new ResponseType("id_token").equals(response.impliedResponseType()));
		assertEquals(ResponseMode.FRAGMENT, response.impliedResponseMode());

		URI responseURI = response.toURI();

		String[] parts = responseURI.toString().split("#");
		assertEquals(REDIRECT_URI.toString(), parts[0]);

		response = AuthenticationSuccessResponse.parse(responseURI);

		assertTrue(response.indicatesSuccess());
		assertEquals(REDIRECT_URI, response.getRedirectionURI());
		assertEquals("https://c2id.com", response.getIDToken().getJWTClaimsSet().getIssuer());
		assertEquals("https://client.com", response.getIDToken().getJWTClaimsSet().getAudience().get(0));
		assertEquals("alice", response.getIDToken().getJWTClaimsSet().getSubject());
		assertEquals(10000l, response.getIDToken().getJWTClaimsSet().getIssueTime().getTime());
		assertEquals(20000l, response.getIDToken().getJWTClaimsSet().getExpirationTime().getTime());
		assertEquals("123", (String)response.getIDToken().getJWTClaimsSet().getClaim("nonce"));
		assertNull(response.getAuthorizationCode());
		assertNull(response.getAccessToken());
		assertEquals("abc", response.getState().getValue());
		assertNull(response.getSessionState());
		assertEquals(ResponseMode.FRAGMENT, response.impliedResponseMode());
	}


	public void testCodeIDTokenResponse()
		throws Exception {

		AuthorizationCode code = new AuthorizationCode();

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer("https://c2id.com")
			.audience(Arrays.asList("https://client.com"))
			.subject("alice")
			.issueTime(new Date(10000l))
			.expirationTime(new Date(20000l))
			.claim("nonce", "123")
			.build();

		SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

		idToken.sign(new MACSigner("01234567890123456789012345678901"));

		AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(
			REDIRECT_URI, code, idToken, null, new State("abc"), null, ResponseMode.FRAGMENT);

		assertTrue(response.indicatesSuccess());
		assertEquals(REDIRECT_URI, response.getRedirectionURI());
		assertEquals(idToken, response.getIDToken());
		assertEquals(code, response.getAuthorizationCode());
		assertNull(response.getAccessToken());
		assertEquals("abc", response.getState().getValue());
		assertNull(response.getSessionState());

		assertTrue(new ResponseType("code", "id_token").equals(response.impliedResponseType()));
		assertEquals(ResponseMode.FRAGMENT, response.impliedResponseMode());

		URI responseURI = response.toURI();

		String[] parts = responseURI.toString().split("#");
		assertEquals(REDIRECT_URI.toString(), parts[0]);

		response = AuthenticationSuccessResponse.parse(responseURI);

		assertTrue(response.indicatesSuccess());
		assertEquals(REDIRECT_URI, response.getRedirectionURI());
		assertEquals("https://c2id.com", response.getIDToken().getJWTClaimsSet().getIssuer());
		assertEquals("https://client.com", response.getIDToken().getJWTClaimsSet().getAudience().get(0));
		assertEquals("alice", response.getIDToken().getJWTClaimsSet().getSubject());
		assertEquals(10000l, response.getIDToken().getJWTClaimsSet().getIssueTime().getTime());
		assertEquals(20000l, response.getIDToken().getJWTClaimsSet().getExpirationTime().getTime());
		assertEquals("123", (String)response.getIDToken().getJWTClaimsSet().getClaim("nonce"));
		assertEquals(code, response.getAuthorizationCode());
		assertNull(response.getAccessToken());
		assertEquals("abc", response.getState().getValue());
		assertNull(response.getSessionState());
		assertEquals(ResponseMode.FRAGMENT, response.impliedResponseMode());
	}


	public void testCodeIDTokenResponseWithSessionState()
		throws Exception {

		AuthorizationCode code = new AuthorizationCode();

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer("https://c2id.com")
			.audience(Arrays.asList("https://client.com"))
			.subject("alice")
			.issueTime(new Date(10000l))
			.expirationTime(new Date(20000l))
			.claim("nonce", "123")
			.build();

		SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

		idToken.sign(new MACSigner("01234567890123456789012345678901"));

		AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(
			REDIRECT_URI, code, idToken, null, new State("abc"), new State("xyz"), ResponseMode.FRAGMENT);

		assertTrue(response.indicatesSuccess());
		assertEquals(REDIRECT_URI, response.getRedirectionURI());
		assertEquals(idToken, response.getIDToken());
		assertEquals(code, response.getAuthorizationCode());
		assertNull(response.getAccessToken());
		assertEquals("abc", response.getState().getValue());
		assertEquals("xyz", response.getSessionState().getValue());

		assertTrue(new ResponseType("code", "id_token").equals(response.impliedResponseType()));
		assertEquals(ResponseMode.FRAGMENT, response.impliedResponseMode());

		URI responseURI = response.toURI();

		String[] parts = responseURI.toString().split("#");
		assertEquals(REDIRECT_URI.toString(), parts[0]);

		response = AuthenticationSuccessResponse.parse(responseURI);

		assertTrue(response.indicatesSuccess());
		assertEquals(REDIRECT_URI, response.getRedirectionURI());
		assertEquals("https://c2id.com", response.getIDToken().getJWTClaimsSet().getIssuer());
		assertEquals("https://client.com", response.getIDToken().getJWTClaimsSet().getAudience().get(0));
		assertEquals("alice", response.getIDToken().getJWTClaimsSet().getSubject());
		assertEquals(10000l, response.getIDToken().getJWTClaimsSet().getIssueTime().getTime());
		assertEquals(20000l, response.getIDToken().getJWTClaimsSet().getExpirationTime().getTime());
		assertEquals("123", (String)response.getIDToken().getJWTClaimsSet().getClaim("nonce"));
		assertEquals(code, response.getAuthorizationCode());
		assertNull(response.getAccessToken());
		assertEquals("abc", response.getState().getValue());
		assertEquals("xyz", response.getSessionState().getValue());
		assertEquals(ResponseMode.FRAGMENT, response.impliedResponseMode());
	}


	public void testCodeResponse()
		throws Exception {

		AuthorizationCode code = new AuthorizationCode();

		AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(
			REDIRECT_URI, code, null, null, new State("abc"), null, ResponseMode.QUERY);

		assertTrue(response.indicatesSuccess());
		assertEquals(REDIRECT_URI, response.getRedirectionURI());
		assertNull(response.getIDToken());
		assertEquals(code, response.getAuthorizationCode());
		assertNull(response.getAccessToken());
		assertEquals("abc", response.getState().getValue());
		assertNull(response.getSessionState());

		assertTrue(new ResponseType("code").equals(response.impliedResponseType()));
		assertEquals(ResponseMode.QUERY, response.impliedResponseMode());

		URI responseURI = response.toURI();

		String[] parts = responseURI.toString().split("\\?");
		assertEquals(REDIRECT_URI.toString(), parts[0]);

		response = AuthenticationSuccessResponse.parse(responseURI);

		assertTrue(response.indicatesSuccess());
		assertEquals(REDIRECT_URI, response.getRedirectionURI());
		assertNull(response.getIDToken());
		assertEquals(code, response.getAuthorizationCode());
		assertNull(response.getAccessToken());
		assertEquals("abc", response.getState().getValue());
		assertNull(response.getSessionState());
		assertEquals(ResponseMode.QUERY, response.impliedResponseMode());
	}


	public void testRedirectionURIWithQueryString()
		throws Exception {
		// See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/140

		URI redirectURI = URI.create("https://example.com/myservice/?action=oidccallback");
		assertEquals("action=oidccallback", redirectURI.getQuery());

		AuthorizationCode code = new AuthorizationCode();
		State state = new State();

		AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(redirectURI, code, null, null, state, null, ResponseMode.QUERY);

		Map<String,String> params = response.toParameters();
		assertEquals(code.getValue(), params.get("code"));
		assertEquals(state.getValue(), params.get("state"));
		assertEquals(2, params.size());

		URI uri = response.toURI();

		params = URLUtils.parseParameters(uri.getQuery());
		assertEquals("oidccallback", params.get("action"));
		assertEquals(code.getValue(), params.get("code"));
		assertEquals(state.getValue(), params.get("state"));
		assertEquals(3, params.size());
	}
}

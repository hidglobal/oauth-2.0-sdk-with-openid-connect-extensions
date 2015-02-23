package com.nimbusds.openid.connect.sdk;


import java.net.URI;
import java.util.Arrays;
import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.State;


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

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setIssuer("https://c2id.com");
		claimsSet.setAudience(Arrays.asList("https://client.com"));
		claimsSet.setSubject("alice");
		claimsSet.setIssueTime(new Date(10000l));
		claimsSet.setExpirationTime(new Date(20000l));
		claimsSet.setClaim("nonce", "123");

		SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

		idToken.sign(new MACSigner("01234567890123456789012345678901"));

		AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(
			REDIRECT_URI, null, idToken, null, new State("abc"));

		assertTrue(response.indicatesSuccess());
		assertEquals(REDIRECT_URI, response.getRedirectionURI());
		assertEquals(idToken, response.getIDToken());
		assertNull(response.getAuthorizationCode());
		assertNull(response.getAccessToken());
		assertEquals("abc", response.getState().getValue());
		assertNull(response.getSessionState());

		assertTrue(new ResponseType("id_token").equals(response.impliedResponseType()));

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
	}


	public void testCodeIDTokenResponse()
		throws Exception {

		AuthorizationCode code = new AuthorizationCode();

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setIssuer("https://c2id.com");
		claimsSet.setAudience(Arrays.asList("https://client.com"));
		claimsSet.setSubject("alice");
		claimsSet.setIssueTime(new Date(10000l));
		claimsSet.setExpirationTime(new Date(20000l));
		claimsSet.setClaim("nonce", "123");

		SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

		idToken.sign(new MACSigner("01234567890123456789012345678901"));

		AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(
			REDIRECT_URI, code, idToken, null, new State("abc"));

		assertTrue(response.indicatesSuccess());
		assertEquals(REDIRECT_URI, response.getRedirectionURI());
		assertEquals(idToken, response.getIDToken());
		assertEquals(code, response.getAuthorizationCode());
		assertNull(response.getAccessToken());
		assertEquals("abc", response.getState().getValue());
		assertNull(response.getSessionState());

		assertTrue(new ResponseType("code", "id_token").equals(response.impliedResponseType()));

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
	}


	public void testCodeIDTokenResponseWithSessionState()
		throws Exception {

		AuthorizationCode code = new AuthorizationCode();

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setIssuer("https://c2id.com");
		claimsSet.setAudience(Arrays.asList("https://client.com"));
		claimsSet.setSubject("alice");
		claimsSet.setIssueTime(new Date(10000l));
		claimsSet.setExpirationTime(new Date(20000l));
		claimsSet.setClaim("nonce", "123");

		SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

		idToken.sign(new MACSigner("01234567890123456789012345678901"));

		AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(
			REDIRECT_URI, code, idToken, null, new State("abc"), new State("xyz"));

		assertTrue(response.indicatesSuccess());
		assertEquals(REDIRECT_URI, response.getRedirectionURI());
		assertEquals(idToken, response.getIDToken());
		assertEquals(code, response.getAuthorizationCode());
		assertNull(response.getAccessToken());
		assertEquals("abc", response.getState().getValue());
		assertEquals("xyz", response.getSessionState().getValue());

		assertTrue(new ResponseType("code", "id_token").equals(response.impliedResponseType()));

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
	}


	public void testCodeResponse()
		throws Exception {

		AuthorizationCode code = new AuthorizationCode();

		AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(
			REDIRECT_URI, code, null, null, new State("abc"));

		assertTrue(response.indicatesSuccess());
		assertEquals(REDIRECT_URI, response.getRedirectionURI());
		assertNull(response.getIDToken());
		assertEquals(code, response.getAuthorizationCode());
		assertNull(response.getAccessToken());
		assertEquals("abc", response.getState().getValue());
		assertNull(response.getSessionState());

		assertTrue(new ResponseType("code").equals(response.impliedResponseType()));

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
	}
}

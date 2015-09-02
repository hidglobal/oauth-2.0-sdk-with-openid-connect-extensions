package com.nimbusds.openid.connect.sdk;


import java.net.URI;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;


/**
 * Tests the logout request class.
 */
public class LogoutRequestTest extends TestCase {


	private static JWT createIDTokenHint()
		throws ParseException {

		Issuer iss = new Issuer("https://c2id.com");
		Subject sub = new Subject("alice");
		List<Audience> audList = Arrays.asList(new Audience("123"));
		Date exp = new Date(2000l);
		Date iat = new Date(1000l);

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(iss, sub, audList, exp, iat);

		return new PlainJWT(claimsSet.toJWTClaimsSet());
	}


	public void testMinimalConstructor()
		throws Exception {

		JWT idToken = createIDTokenHint();

		URI endpoint = new URI("https://c2id.com/logout");

		LogoutRequest request = new LogoutRequest(endpoint, idToken);

		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(idToken, request.getIDTokenHint());
		assertNull(request.getPostLogoutRedirectionURI());
		assertNull(request.getState());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());

		request = LogoutRequest.parse(httpRequest);

		assertEquals(Algorithm.NONE, request.getIDTokenHint().getHeader().getAlgorithm());
		assertEquals(idToken.getJWTClaimsSet().getIssuer(), request.getIDTokenHint().getJWTClaimsSet().getIssuer());
		assertEquals(idToken.getJWTClaimsSet().getSubject(), request.getIDTokenHint().getJWTClaimsSet().getSubject());
		assertEquals(idToken.getJWTClaimsSet().getAudience().get(0), request.getIDTokenHint().getJWTClaimsSet().getAudience().get(0));
		assertEquals(idToken.getJWTClaimsSet().getExpirationTime(), request.getIDTokenHint().getJWTClaimsSet().getExpirationTime());
		assertEquals(idToken.getJWTClaimsSet().getIssueTime(), request.getIDTokenHint().getJWTClaimsSet().getIssueTime());
		assertNull(request.getPostLogoutRedirectionURI());
		assertNull(request.getState());
	}


	public void testFullConstructor()
		throws Exception {

		JWT idToken = createIDTokenHint();

		URI postLogoutRedirectURI = new URI("https://client.com/post-logout");
		State state = new State();

		URI endpoint = new URI("https://c2id.com/logout");

		LogoutRequest request = new LogoutRequest(endpoint, idToken, postLogoutRedirectURI, state);

		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(idToken, request.getIDTokenHint());
		assertEquals(postLogoutRedirectURI, request.getPostLogoutRedirectionURI());
		assertEquals(state, request.getState());

		Map<String,String> params = request.toParameters();
		assertEquals(idToken.serialize(), params.get("id_token_hint"));
		assertEquals(postLogoutRedirectURI.toString(), params.get("post_logout_redirect_uri"));
		assertEquals(state.getValue(), params.get("state"));
		assertEquals(3, params.size());

		URI outputURI = request.toURI();

		assertTrue(outputURI.toString().startsWith("https://c2id.com/logout"));
		params = URLUtils.parseParameters(outputURI.getQuery());
		assertEquals(idToken.serialize(), params.get("id_token_hint"));
		assertEquals(postLogoutRedirectURI.toString(), params.get("post_logout_redirect_uri"));
		assertEquals(state.getValue(), params.get("state"));
		assertEquals(3, params.size());

		request = LogoutRequest.parse(outputURI);

		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(idToken.serialize(), request.getIDTokenHint().serialize());
		assertEquals(postLogoutRedirectURI, request.getPostLogoutRedirectionURI());
		assertEquals(state, request.getState());
	}


	public void testRejectUnsignedIDToken()
		throws Exception {

		Issuer iss = new Issuer("https://c2id.com");
		Subject sub = new Subject("alice");
		List<Audience> audList = Arrays.asList(new Audience("123"));
		Date exp = new Date(2000l);
		Date iat = new Date(1000l);

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(iss, sub, audList, exp, iat);

		SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet.toJWTClaimsSet());

		URI postLogoutRedirectURI = new URI("https://client.com/post-logout");

		URI endpoint = new URI("https://c2id.com/logout");

		try {
			new LogoutRequest(endpoint, idToken, postLogoutRedirectURI, null).toQueryString();
			fail();
		} catch (SerializeException e) {
			// ok
		}
	}


	public void testRejectStateWithoutRedirectionURI()
		throws Exception {

		JWT idToken = createIDTokenHint();

		URI endpoint = new URI("https://c2id.com/logout");

		try {
			new LogoutRequest(endpoint, idToken, null, new State());
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The state parameter required a post-logout redirection URI", e.getMessage());
		}
	}


	public void testMissingIDTokenHint()
		throws Exception {

		try {
			new LogoutRequest(new URI("https://c2id.com/logout"), null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The ID token hint must not be null", e.getMessage());
		}
	}


	// See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/147/authorizationrequestparse-final-uri-uri
	public void testParseWithEncodedEqualsChar()
		throws Exception {

		JWT idToken = createIDTokenHint();

		URI postLogoutRedirectURI = URI.create("https://client.com/post-logout?app=123");

		String encodedPostLogoutRedirectURI = URLEncoder.encode(postLogoutRedirectURI.toString(), "UTF-8");

		URI requestURI = URI.create("https://server.example.com/logout?" +
			"id_token_hint=" + idToken.serialize() +
			"&post_logout_redirect_uri=" + encodedPostLogoutRedirectURI);

		LogoutRequest request = LogoutRequest.parse(requestURI);

		assertEquals(postLogoutRedirectURI, request.getPostLogoutRedirectionURI());
		assertNull(request.getState());
		assertNotNull(request.getIDTokenHint());
		assertEquals("https://server.example.com/logout", request.getEndpointURI().toString());
	}
}

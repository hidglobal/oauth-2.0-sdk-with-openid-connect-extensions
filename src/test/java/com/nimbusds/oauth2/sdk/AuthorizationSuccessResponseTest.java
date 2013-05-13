package com.nimbusds.oauth2.sdk;


import java.net.MalformedURLException;
import java.net.URL;

import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import com.nimbusds.oauth2.sdk.id.State;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


/**
 * Tests authorisation response serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-19)
 */
public class AuthorizationSuccessResponseTest extends TestCase {
	
	
	private static URL ABS_REDIRECT_URL = null;
	
	
	private static URL REL_REDIRECT_URL = null;


	private static AuthorizationCode CODE = new AuthorizationCode("SplxlOBeZQQYbYS6WxSbIA");


	private static AccessToken TOKEN = new BearerAccessToken("2YotnFZFEjr1zCsicMWpAA", 3600, null);


	private static State STATE = new State("xyz");


	private static String RESPONSE_CODE = 
		"https://client.example.org/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz";


	private static String RESPONSE_TOKEN = 
		"https://client.example.org/cb#" +
		"&access_token=2YotnFZFEjr1zCsicMWpAA" +
		"&token_type=Bearer" +
		"&expires_in=3600" +
		"&state=xyz";
	
	
	public void setUp()
		throws MalformedURLException, 
		       java.text.ParseException {
		
		ABS_REDIRECT_URL = new URL("https://client.example.org/cb");
		
		REL_REDIRECT_URL = new URL("https://");
	}
	
	
	public void testCodeFlow()
		throws Exception {
	
		AuthorizationSuccessResponse resp = new AuthorizationSuccessResponse(ABS_REDIRECT_URL, CODE, STATE);

		assertEquals(ABS_REDIRECT_URL, resp.getRedirectURI());
		assertEquals(CODE, resp.getAuthorizationCode());
		assertEquals(STATE, resp.getState());
		assertNull(resp.getAccessToken());

		Map<String,String> params = resp.toParameters();
		assertEquals(CODE, new AuthorizationCode(params.get("code")));
		assertEquals(STATE, new State(params.get("state")));
		assertEquals(2, params.size());

		URL uri = resp.toURI();

		System.out.println("Location: " + uri);

		HTTPResponse httpResponse = resp.toHTTPResponse();
		assertEquals(302, httpResponse.getStatusCode());
		assertEquals(uri, httpResponse.getLocation());

		resp = AuthorizationSuccessResponse.parse(httpResponse);

		assertEquals(ABS_REDIRECT_URL, resp.getRedirectURI());
		assertEquals(CODE, resp.getAuthorizationCode());
		assertEquals(STATE, resp.getState());
		assertNull(resp.getAccessToken());
	}


	public void testImplicitFlow()
		throws Exception {
	
		AuthorizationSuccessResponse resp = new AuthorizationSuccessResponse(ABS_REDIRECT_URL, TOKEN, STATE);

		assertEquals(ABS_REDIRECT_URL, resp.getRedirectURI());
		assertEquals(TOKEN, resp.getAccessToken());
		assertEquals(3600, resp.getAccessToken().getLifetime());
		assertEquals(STATE, resp.getState());
		assertNull(resp.getAuthorizationCode());

		Map<String,String> params = resp.toParameters();
		assertEquals(TOKEN.getValue(), params.get("access_token"));
		assertEquals(STATE, new State(params.get("state")));
		assertEquals(TOKEN.getType(), new AccessTokenType((String)params.get("token_type")));
		assertEquals("3600", params.get("expires_in"));
		assertEquals(4, params.size());

		URL uri = resp.toURI();

		System.out.println("Location: " + uri);

		HTTPResponse httpResponse = resp.toHTTPResponse();
		assertEquals(302, httpResponse.getStatusCode());
		assertEquals(uri, httpResponse.getLocation());

		resp = AuthorizationSuccessResponse.parse(httpResponse);

		assertEquals(ABS_REDIRECT_URL, resp.getRedirectURI());
		assertEquals(TOKEN, resp.getAccessToken());
		assertEquals(3600, resp.getAccessToken().getLifetime());
		assertEquals(STATE, resp.getState());
		assertNull(resp.getAuthorizationCode());
	}
}

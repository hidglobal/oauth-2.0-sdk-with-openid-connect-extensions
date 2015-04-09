package com.nimbusds.oauth2.sdk;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


/**
 * Tests authorisation response serialisation and parsing.
 */
public class AuthorizationSuccessResponseTest extends TestCase {
	
	
	private static URI ABS_REDIRECT_URI = null;


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
		throws URISyntaxException,
		       java.text.ParseException {
		
		ABS_REDIRECT_URI = new URI("https://client.example.org/cb");
	}
	
	
	public void testCodeFlow()
		throws Exception {
	
		AuthorizationSuccessResponse resp = new AuthorizationSuccessResponse(ABS_REDIRECT_URI, CODE, null, STATE, null);

		assertTrue(resp.indicatesSuccess());
		assertEquals(ABS_REDIRECT_URI, resp.getRedirectionURI());
		assertEquals(CODE, resp.getAuthorizationCode());
		assertEquals(STATE, resp.getState());
		assertNull(resp.getAccessToken());
		assertNull(resp.getResponseMode());

		ResponseType responseType = resp.impliedResponseType();
		assertTrue(new ResponseType("code").equals(responseType));

		assertEquals(ResponseMode.QUERY, resp.impliedResponseMode());

		Map<String,String> params = resp.toParameters();
		assertEquals(CODE, new AuthorizationCode(params.get("code")));
		assertEquals(STATE, new State(params.get("state")));
		assertEquals(2, params.size());

		URI uri = resp.toURI();

		HTTPResponse httpResponse = resp.toHTTPResponse();
		assertEquals(302, httpResponse.getStatusCode());
		assertEquals(uri.toString(), httpResponse.getLocation().toString());

		resp = AuthorizationSuccessResponse.parse(httpResponse);

		assertTrue(resp.indicatesSuccess());
		assertEquals(ABS_REDIRECT_URI, resp.getRedirectionURI());
		assertEquals(CODE, resp.getAuthorizationCode());
		assertEquals(STATE, resp.getState());
		assertNull(resp.getAccessToken());
		assertNull(resp.getResponseMode());

		assertEquals(ResponseMode.QUERY, resp.impliedResponseMode());
	}


	public void testImplicitFlow()
		throws Exception {
	
		AuthorizationSuccessResponse resp = new AuthorizationSuccessResponse(ABS_REDIRECT_URI, null, TOKEN, STATE, null);

		assertTrue(resp.indicatesSuccess());
		assertEquals(ABS_REDIRECT_URI, resp.getRedirectionURI());
		assertEquals(TOKEN, resp.getAccessToken());
		assertEquals(3600, resp.getAccessToken().getLifetime());
		assertEquals(STATE, resp.getState());
		assertNull(resp.getAuthorizationCode());
		assertNull(resp.getResponseMode());

		ResponseType responseType = resp.impliedResponseType();
		assertTrue(new ResponseType("token").equals(responseType));

		assertEquals(ResponseMode.FRAGMENT, resp.impliedResponseMode());

		Map<String,String> params = resp.toParameters();
		assertEquals(TOKEN.getValue(), params.get("access_token"));
		assertEquals(STATE, new State(params.get("state")));
		assertEquals(TOKEN.getType(), new AccessTokenType(params.get("token_type")));
		assertEquals("3600", params.get("expires_in"));
		assertEquals(4, params.size());

		URI uri = resp.toURI();

		System.out.println("Location: " + uri);

		HTTPResponse httpResponse = resp.toHTTPResponse();
		assertEquals(302, httpResponse.getStatusCode());
		assertEquals(uri, httpResponse.getLocation());

		resp = AuthorizationSuccessResponse.parse(httpResponse);

		assertTrue(resp.indicatesSuccess());
		assertEquals(ABS_REDIRECT_URI, resp.getRedirectionURI());
		assertEquals(TOKEN, resp.getAccessToken());
		assertEquals(3600, resp.getAccessToken().getLifetime());
		assertEquals(STATE, resp.getState());
		assertNull(resp.getAuthorizationCode());
		assertNull(resp.getResponseMode());

		assertEquals(ResponseMode.FRAGMENT, resp.impliedResponseMode());
	}


	public void testResponseModeFormPost()
		throws Exception {

		AuthorizationSuccessResponse resp = new AuthorizationSuccessResponse(
			ABS_REDIRECT_URI,
			null,
			TOKEN,
			STATE,
			ResponseMode.FORM_POST);

		ResponseType responseType = resp.impliedResponseType();
		assertTrue(new ResponseType("token").equals(responseType));

		assertEquals(ResponseMode.FORM_POST, resp.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, resp.impliedResponseMode());

		try {
			resp.toURI();
			fail();
		} catch (SerializeException e) {
			// ok
		}

		HTTPRequest httpRequest = resp.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertEquals(ABS_REDIRECT_URI, httpRequest.getURL().toURI());

		assertEquals("Bearer", httpRequest.getQueryParameters().get("token_type"));
		assertEquals(TOKEN.getLifetime() + "", httpRequest.getQueryParameters().get("expires_in"));
		assertEquals(TOKEN.getValue(), httpRequest.getQueryParameters().get("access_token"));
		assertEquals(STATE.getValue(), httpRequest.getQueryParameters().get("state"));
		assertEquals(4, httpRequest.getQueryParameters().size());
	}


	public void testOverrideQueryResponseMode()
		throws Exception {

		AuthorizationSuccessResponse resp = new AuthorizationSuccessResponse(
			ABS_REDIRECT_URI,
			CODE,
			null,
			STATE,
			ResponseMode.FRAGMENT);

		ResponseType responseType = resp.impliedResponseType();
		assertTrue(new ResponseType("code").equals(responseType));

		assertEquals(ResponseMode.FRAGMENT, resp.getResponseMode());
		assertEquals(ResponseMode.FRAGMENT, resp.impliedResponseMode());

		try {
			resp.toHTTPRequest();
			fail();
		} catch (SerializeException e) {
			// ok
		}

		URI uri = resp.toURI();
		assertNull(uri.getQuery());
		Map<String,String> params = URLUtils.parseParameters(uri.getRawFragment());
		assertEquals(CODE.getValue(), params.get("code"));
		assertEquals(STATE.getValue(), params.get("state"));
		assertEquals(2, params.size());
	}


	public void testOverrideFragmentResponseMode()
		throws Exception {

		AuthorizationSuccessResponse resp = new AuthorizationSuccessResponse(
			ABS_REDIRECT_URI,
			null,
			TOKEN,
			STATE,
			ResponseMode.QUERY);

		ResponseType responseType = resp.impliedResponseType();
		assertTrue(new ResponseType("token").equals(responseType));

		assertEquals(ResponseMode.QUERY, resp.getResponseMode());
		assertEquals(ResponseMode.QUERY, resp.impliedResponseMode());

		try {
			resp.toHTTPRequest();
			fail();
		} catch (SerializeException e) {
			// ok
		}

		URI uri = resp.toURI();
		assertNull(uri.getRawFragment());
		Map<String,String> params = URLUtils.parseParameters(uri.getQuery());
		assertEquals("Bearer", params.get("token_type"));
		assertEquals(TOKEN.getValue(), params.get("access_token"));
		assertEquals(TOKEN.getLifetime() + "", params.get("expires_in"));
		assertEquals(STATE.getValue(), params.get("state"));
		assertEquals(4, params.size());
	}


	public void testParseCodeResponse()
		throws Exception {

		URI redirectionURI = new URI(RESPONSE_CODE);

		AuthorizationSuccessResponse response = AuthorizationSuccessResponse.parse(redirectionURI);
		assertTrue(response.indicatesSuccess());
		assertEquals("https://client.example.org/cb", response.getRedirectionURI().toString());
		assertEquals("SplxlOBeZQQYbYS6WxSbIA", response.getAuthorizationCode().getValue());
		assertEquals("xyz", response.getState().getValue());
		assertNull(response.getAccessToken());
	}


	public void testParseTokenResponse()
		throws Exception {

		URI redirectionURI = new URI(RESPONSE_TOKEN);

		AuthorizationSuccessResponse response = AuthorizationSuccessResponse.parse(redirectionURI);
		assertTrue(response.indicatesSuccess());
		assertEquals("https://client.example.org/cb", response.getRedirectionURI().toString());
		assertNull(response.getAuthorizationCode());
		assertEquals("xyz", response.getState().getValue());
		BearerAccessToken accessToken = (BearerAccessToken)response.getAccessToken();
		assertEquals("2YotnFZFEjr1zCsicMWpAA", accessToken.getValue());
		assertEquals(3600l, accessToken.getLifetime());
	}
}

package com.nimbusds.oauth2.sdk;


import java.net.URL;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.RefreshToken;


/**
 * Tests access and refresh token request serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-05-10)
 */
public class TokenRequestTest extends TestCase {
	
	
	public void testAccessTokenRequestWithBasicSecret()
		throws Exception {
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);
		
		String postBody = 
			"grant_type=authorization_code" +
			"&code=SplxlOBeZQQYbYS6WxSbIA" +
			"&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb";
		
		httpRequest.setQuery(postBody);
		
		TokenRequest tr = TokenRequest.parse(httpRequest);
		
		assertTrue(tr instanceof AccessTokenRequest);
		
		assertEquals(GrantType.AUTHORIZATION_CODE, tr.getGrantType());
		assertTrue(tr.getClientAuthentication() instanceof ClientSecretBasic);
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, tr.getClientAuthentication().getMethod());
		
		ClientSecretBasic authBasic = (ClientSecretBasic)tr.getClientAuthentication();
	
		assertEquals("Basic " + authBasicString, authBasic.toHTTPAuthorizationHeader());
		
		System.out.println("Access Token request: Client ID: " + authBasic.getClientID().getValue());
		assertEquals("s6BhdRkqt3", authBasic.getClientID().getValue());
		
		System.out.println("Access Token request: Client secret: " + authBasic.getClientSecret());
		
		AccessTokenRequest atr = (AccessTokenRequest)tr;
		
		AuthorizationCode code = atr.getAuthorizationCode();
		assertEquals("SplxlOBeZQQYbYS6WxSbIA", code.getValue());
		
		assertEquals("https://client.example.com/cb", atr.getRedirectURI().toString());
		
		
		httpRequest = atr.toHTTPRequest(new URL("https://connect2id.com/token/"));
		
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED, httpRequest.getContentType());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals(postBody, httpRequest.getQuery());
	}
	
	
	public void testRefreshTokenRequestWithBasicSecret()
		throws Exception {
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		final String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);
		
		final String postBody = 
			"grant_type=refresh_token" +
			"&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA";
		
		httpRequest.setQuery(postBody);
		
		TokenRequest tr = TokenRequest.parse(httpRequest);
		
		assertTrue(tr instanceof RefreshTokenRequest);
		
		assertEquals(GrantType.REFRESH_TOKEN, tr.getGrantType());
		assertTrue(tr.getClientAuthentication() instanceof ClientSecretBasic);
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, tr.getClientAuthentication().getMethod());
		
		ClientSecretBasic authBasic = (ClientSecretBasic)tr.getClientAuthentication();
	
		assertEquals("Basic " + authBasicString, authBasic.toHTTPAuthorizationHeader());
		
		System.out.println("Access Token request: Client ID: " + authBasic.getClientID().getValue());
		assertEquals("s6BhdRkqt3", authBasic.getClientID().getValue());
		
		System.out.println("Access Token request: Client secret: " + authBasic.getClientSecret());
		
		RefreshTokenRequest rtr = (RefreshTokenRequest)tr;
		
		RefreshToken token = rtr.getRefreshToken();
		assertEquals("tGzv3JOkF0XG5Qx2TlKWIA", token.getValue());
		
		httpRequest = rtr.toHTTPRequest(new URL("https://connect2id.com/token/"));
		
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED, httpRequest.getContentType());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals(postBody, httpRequest.getQuery());
	}
}

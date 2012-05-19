package com.nimbusds.openid.connect.messages;


import junit.framework.TestCase;

import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.http.CommonContentTypes;
import com.nimbusds.openid.connect.http.HTTPRequest;


/**
 * Tests access and refresh token request serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.2 (2012-05-19)
 */
public class TokenRequestTest extends TestCase {
	
	
	public void testAccessTokenRequestWithBasicSecret() {
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST);
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		final String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);
		
		final String postBody = 
			"grant_type=authorization_code" +
			"&code=SplxlOBeZQQYbYS6WxSbIA" +
			"&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb";
		
		httpRequest.setQuery(postBody);
		
		TokenRequest tr = null;
		
		try {
			tr = TokenRequest.parse(httpRequest);
		
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertTrue(tr instanceof AccessTokenRequest);
		
		assertEquals(GrantType.AUTHORIZATION_CODE, tr.getGrantType());
		assertTrue(tr.getClientAuthentication() instanceof ClientSecretBasic);
		assertEquals(ClientAuthentication.Method.CLIENT_SECRET_BASIC, tr.getClientAuthentication().getMethod());
		
		ClientSecretBasic authBasic = (ClientSecretBasic)tr.getClientAuthentication();
	
		assertEquals("Basic " + authBasicString, authBasic.toHTTPAuthorizationHeader());
		
		System.out.println("Access Token request: Client ID: " + authBasic.getClientID().getClaimValue());
		assertEquals("s6BhdRkqt3", authBasic.getClientID().getClaimValue());
		
		System.out.println("Access Token request: Client secret: " + authBasic.getClientSecret());
		
		AccessTokenRequest atr = (AccessTokenRequest)tr;
		
		AuthorizationCode code = atr.getAuthorizationCode();
		assertEquals("SplxlOBeZQQYbYS6WxSbIA", code.getValue());
		
		assertEquals("https://client.example.com/cb", atr.getRedirectURI().toString());
		
		
		try {
			httpRequest = atr.toHTTPRequest();
			
		} catch (SerializeException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED, httpRequest.getContentType());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals(postBody, httpRequest.getQuery());
	}
	
	
	public void testRefreshTokenRequestWithBasicSecret() {
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST);
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		final String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);
		
		final String postBody = 
			"grant_type=refresh_token" +
			"&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA";
		
		httpRequest.setQuery(postBody);
		
		TokenRequest tr = null;
		
		try {
			tr = TokenRequest.parse(httpRequest);
			
		} catch (ParseException e) {
		
			fail(e.getMessage());
		}
		
		assertTrue(tr instanceof RefreshTokenRequest);
		
		assertEquals(GrantType.REFRESH_TOKEN, tr.getGrantType());
		assertTrue(tr.getClientAuthentication() instanceof ClientSecretBasic);
		assertEquals(ClientAuthentication.Method.CLIENT_SECRET_BASIC, tr.getClientAuthentication().getMethod());
		
		ClientSecretBasic authBasic = (ClientSecretBasic)tr.getClientAuthentication();
	
		assertEquals("Basic " + authBasicString, authBasic.toHTTPAuthorizationHeader());
		
		System.out.println("Access Token request: Client ID: " + authBasic.getClientID().getClaimValue());
		assertEquals("s6BhdRkqt3", authBasic.getClientID().getClaimValue());
		
		System.out.println("Access Token request: Client secret: " + authBasic.getClientSecret());
		
		RefreshTokenRequest rtr = (RefreshTokenRequest)tr;
		
		RefreshToken token = rtr.getRefreshToken();
		assertEquals("tGzv3JOkF0XG5Qx2TlKWIA", token.getValue());
		
		try {
			httpRequest = rtr.toHTTPRequest();
			
		} catch (SerializeException e) {
		
			fail(e.getMessage());
		}
		
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED, httpRequest.getContentType());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals(postBody, httpRequest.getQuery());
	}
}

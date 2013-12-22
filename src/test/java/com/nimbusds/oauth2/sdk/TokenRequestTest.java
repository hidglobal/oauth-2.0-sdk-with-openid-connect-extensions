package com.nimbusds.oauth2.sdk;


import java.net.URL;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;


/**
 * Tests access and refresh token request serialisation and parsing.
 */
public class TokenRequestTest extends TestCase {
	
	
	public void testCodeGrantWithBasicSecret()
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

		assertTrue(new URL("https://connect2id.com/token/").equals(tr.getEndpointURI()));

		ClientSecretBasic authBasic = (ClientSecretBasic)tr.getClientAuthentication();
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, authBasic.getMethod());
		assertEquals("Basic " + authBasicString, authBasic.toHTTPAuthorizationHeader());
		assertEquals("s6BhdRkqt3", authBasic.getClientID().getValue());

		AuthorizationCodeGrant codeGrant = (AuthorizationCodeGrant)tr.getAuthorizationGrant();
		assertEquals(GrantType.AUTHORIZATION_CODE, codeGrant.getType());
		assertEquals("SplxlOBeZQQYbYS6WxSbIA", codeGrant.getAuthorizationCode().getValue());
		assertEquals("https://client.example.com/cb", codeGrant.getRedirectionURI().toString());
		assertNull(codeGrant.getClientID());
		
		httpRequest = tr.toHTTPRequest();
		
		assertTrue(new URL("https://connect2id.com/token/").equals(httpRequest.getURL()));
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED, httpRequest.getContentType());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals(postBody, httpRequest.getQuery());
	}
	
	
	public void testRefreshTokenGrantWithBasicSecret()
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

		assertTrue(new URL("https://connect2id.com/token/").equals(tr.getEndpointURI()));

		ClientSecretBasic authBasic = (ClientSecretBasic)tr.getClientAuthentication();
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, authBasic.getMethod());
		assertEquals("Basic " + authBasicString, authBasic.toHTTPAuthorizationHeader());
		assertEquals("s6BhdRkqt3", authBasic.getClientID().getValue());

		RefreshTokenGrant rtGrant = (RefreshTokenGrant)tr.getAuthorizationGrant();
		assertEquals(GrantType.REFRESH_TOKEN, rtGrant.getType());
		assertEquals("tGzv3JOkF0XG5Qx2TlKWIA", rtGrant.getRefreshToken().getValue());
		
		httpRequest = tr.toHTTPRequest();

		assertTrue(new URL("https://connect2id.com/token/").equals(httpRequest.getURL()));
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED, httpRequest.getContentType());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals(postBody, httpRequest.getQuery());
	}


	public void testPasswordCredentialsGrant()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		final String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);

		final String postBody = "grant_type=password&username=johndoe&password=A3ddj3w";

		httpRequest.setQuery(postBody);

		TokenRequest tr = TokenRequest.parse(httpRequest);

		assertTrue(new URL("https://connect2id.com/token/").equals(tr.getEndpointURI()));

		ClientSecretBasic authBasic = (ClientSecretBasic)tr.getClientAuthentication();
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, authBasic.getMethod());
		assertEquals("Basic " + authBasicString, authBasic.toHTTPAuthorizationHeader());
		assertEquals("s6BhdRkqt3", authBasic.getClientID().getValue());

		ResourceOwnerPasswordCredentialsGrant pwdGrant = (ResourceOwnerPasswordCredentialsGrant)tr.getAuthorizationGrant();
		assertEquals(GrantType.PASSWORD, pwdGrant.getType());
		assertEquals("johndoe", pwdGrant.getUsername());
		assertEquals("A3ddj3w", pwdGrant.getPassword().getValue());
		assertNull(pwdGrant.getScope());

		httpRequest = tr.toHTTPRequest();

		assertTrue(new URL("https://connect2id.com/token/").equals(httpRequest.getURL()));
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED, httpRequest.getContentType());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals(postBody, httpRequest.getQuery());
	}


	public void testClientCredentialsGrant()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		final String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);

		final String postBody = "grant_type=client_credentials";

		httpRequest.setQuery(postBody);

		TokenRequest tr = TokenRequest.parse(httpRequest);

		assertTrue(new URL("https://connect2id.com/token/").equals(tr.getEndpointURI()));

		ClientSecretBasic authBasic = (ClientSecretBasic)tr.getClientAuthentication();
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, authBasic.getMethod());
		assertEquals("Basic " + authBasicString, authBasic.toHTTPAuthorizationHeader());
		assertEquals("s6BhdRkqt3", authBasic.getClientID().getValue());

		ClientCredentialsGrant clientCredentialsGrant = (ClientCredentialsGrant)tr.getAuthorizationGrant();
		assertEquals(GrantType.CLIENT_CREDENTIALS, clientCredentialsGrant.getType());
		assertNull(clientCredentialsGrant.getScope());

		httpRequest = tr.toHTTPRequest();

		assertTrue(new URL("https://connect2id.com/token/").equals(httpRequest.getURL()));
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED, httpRequest.getContentType());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals(postBody, httpRequest.getQuery());
	}
}

package com.nimbusds.oauth2.sdk;


import java.net.URI;
import java.net.URL;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.auth.*;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;


/**
 * Tests token request serialisation and parsing.
 */
public class TokenRequestTest extends TestCase {


	public void testConstructorWithClientAuthentication()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID("123"), new Secret("secret"));
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), null);
		Scope scope = Scope.parse("openid email");

		TokenRequest request = new TokenRequest(uri, clientAuth, grant, scope);

		assertEquals(uri, request.getEndpointURI());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertEquals(scope, request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		ClientSecretBasic basic = ClientSecretBasic.parse(httpRequest.getAuthorization());
		assertEquals("123", basic.getClientID().getValue());
		assertEquals("secret", basic.getClientSecret().getValue());
		Map<String,String> params = httpRequest.getQueryParameters();
		assertEquals(GrantType.AUTHORIZATION_CODE.getValue(), params.get("grant_type"));
		assertEquals("abc", params.get("code"));
		assertTrue(Scope.parse("openid email").containsAll(Scope.parse(params.get("scope"))));
		assertEquals(3, params.size());
	}


	public void testConstructorWithClientAuthenticationAndNoScope()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID("123"), new Secret("secret"));
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), null);

		TokenRequest request = new TokenRequest(uri, clientAuth, grant);

		assertEquals(uri, request.getEndpointURI());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		ClientSecretBasic basic = ClientSecretBasic.parse(httpRequest.getAuthorization());
		assertEquals("123", basic.getClientID().getValue());
		assertEquals("secret", basic.getClientSecret().getValue());
		Map<String,String> params = httpRequest.getQueryParameters();
		assertEquals(GrantType.AUTHORIZATION_CODE.getValue(), params.get("grant_type"));
		assertEquals("abc", params.get("code"));
		assertEquals(2, params.size());
	}


	public void testRejectNullClientAuthentication()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");

		try {
			new TokenRequest(uri, (ClientAuthentication)null, new ClientCredentialsGrant(), null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The client authentication must not be null", e.getMessage());
		}
	}


	public void testConstructorWithClientID()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), new URI("http://example.com/in"));

		TokenRequest request = new TokenRequest(uri, clientID, grant, null);

		assertEquals(uri, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(clientID, request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertNull(httpRequest.getAuthorization());
		Map<String,String> params = httpRequest.getQueryParameters();
		assertEquals(GrantType.AUTHORIZATION_CODE.getValue(), params.get("grant_type"));
		assertEquals("abc", params.get("code"));
		assertEquals("123", params.get("client_id"));
		assertEquals("http://example.com/in", params.get("redirect_uri"));
		assertEquals(4, params.size());
	}


	public void testConstructorWithClientIDAndNoScope()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), new URI("http://example.com/in"));

		TokenRequest request = new TokenRequest(uri, clientID, grant);

		assertEquals(uri, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(clientID, request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertNull(httpRequest.getAuthorization());
		Map<String,String> params = httpRequest.getQueryParameters();
		assertEquals(GrantType.AUTHORIZATION_CODE.getValue(), params.get("grant_type"));
		assertEquals("abc", params.get("code"));
		assertEquals("123", params.get("client_id"));
		assertEquals("http://example.com/in", params.get("redirect_uri"));
		assertEquals(4, params.size());
	}


	public void testConstructorMissingClientID()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientID clientID = null;
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), new URI("http://example.com/in"));

		try {
			new TokenRequest(uri, clientID, grant, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The \"authorization_code\" grant type requires a \"client_id\" parameter", e.getMessage());
		}
	}


	public void testMinimalConstructor()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		AuthorizationGrant grant = new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("secret"));
		Scope scope = Scope.parse("openid email");

		TokenRequest tokenRequest = new TokenRequest(uri, grant, scope);

		assertEquals(uri, tokenRequest.getEndpointURI());
		assertNull(tokenRequest.getClientAuthentication());
		assertNull(tokenRequest.getClientID());
		assertEquals(grant, tokenRequest.getAuthorizationGrant());
		assertEquals(scope, tokenRequest.getScope());

		HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertNull(httpRequest.getAuthorization());
		Map<String,String> params = httpRequest.getQueryParameters();
		assertEquals(GrantType.PASSWORD.getValue(), params.get("grant_type"));
		assertEquals("alice", params.get("username"));
		assertEquals("secret", params.get("password"));
		assertTrue(Scope.parse("openid email").containsAll(Scope.parse(params.get("scope"))));
		assertEquals(4, params.size());
	}


	public void testMinimalConstructorWithNoScope()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		AuthorizationGrant grant = new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("secret"));

		TokenRequest tokenRequest = new TokenRequest(uri, grant);

		assertEquals(uri, tokenRequest.getEndpointURI());
		assertNull(tokenRequest.getClientAuthentication());
		assertNull(tokenRequest.getClientID());
		assertEquals(grant, tokenRequest.getAuthorizationGrant());
		assertNull(tokenRequest.getScope());

		HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertNull(httpRequest.getAuthorization());
		Map<String,String> params = httpRequest.getQueryParameters();
		assertEquals(GrantType.PASSWORD.getValue(), params.get("grant_type"));
		assertEquals("alice", params.get("username"));
		assertEquals("secret", params.get("password"));
		assertEquals(3, params.size());
	}


	public void testMissingClientCredentialsAuthentication()
		throws Exception {

		try {
			new TokenRequest(new URI("https://c2id.com/token"), new ClientCredentialsGrant(), null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The \"client_credentials\" grant type requires client authentication", e.getMessage());
		}
	}
	
	
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

		assertTrue(new URI("https://connect2id.com/token/").equals(tr.getEndpointURI()));

		ClientSecretBasic authBasic = (ClientSecretBasic)tr.getClientAuthentication();
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, authBasic.getMethod());
		assertEquals("Basic " + authBasicString, authBasic.toHTTPAuthorizationHeader());
		assertEquals("s6BhdRkqt3", authBasic.getClientID().getValue());

		AuthorizationCodeGrant codeGrant = (AuthorizationCodeGrant)tr.getAuthorizationGrant();
		assertEquals(GrantType.AUTHORIZATION_CODE, codeGrant.getType());
		assertEquals("SplxlOBeZQQYbYS6WxSbIA", codeGrant.getAuthorizationCode().getValue());
		assertEquals("https://client.example.com/cb", codeGrant.getRedirectionURI().toString());

		assertNull(tr.getClientID());
		
		httpRequest = tr.toHTTPRequest();
		
		assertTrue(new URL("https://connect2id.com/token/").equals(httpRequest.getURL()));
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals("authorization_code", httpRequest.getQueryParameters().get("grant_type"));
		assertEquals("SplxlOBeZQQYbYS6WxSbIA", httpRequest.getQueryParameters().get("code"));
		assertEquals("https://client.example.com/cb", httpRequest.getQueryParameters().get("redirect_uri"));
		assertEquals(3, httpRequest.getQueryParameters().size());
	}
	
	
	public void testParseRefreshTokenGrantWithBasicSecret()
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

		assertTrue(new URI("https://connect2id.com/token/").equals(tr.getEndpointURI()));

		ClientSecretBasic authBasic = (ClientSecretBasic)tr.getClientAuthentication();
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, authBasic.getMethod());
		assertEquals("Basic " + authBasicString, authBasic.toHTTPAuthorizationHeader());
		assertEquals("s6BhdRkqt3", authBasic.getClientID().getValue());

		RefreshTokenGrant rtGrant = (RefreshTokenGrant)tr.getAuthorizationGrant();
		assertEquals(GrantType.REFRESH_TOKEN, rtGrant.getType());
		assertEquals("tGzv3JOkF0XG5Qx2TlKWIA", rtGrant.getRefreshToken().getValue());
		
		httpRequest = tr.toHTTPRequest();

		assertTrue(new URL("https://connect2id.com/token/").equals(httpRequest.getURL()));
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals(postBody, httpRequest.getQuery());
	}


	public void testParsePasswordCredentialsGrant()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		final String postBody = "grant_type=password&username=johndoe&password=A3ddj3w";

		httpRequest.setQuery(postBody);

		TokenRequest tr = TokenRequest.parse(httpRequest);

		assertTrue(new URI("https://connect2id.com/token/").equals(tr.getEndpointURI()));

		assertNull(tr.getClientAuthentication());
		assertNull(tr.getClientID());

		ResourceOwnerPasswordCredentialsGrant pwdGrant = (ResourceOwnerPasswordCredentialsGrant)tr.getAuthorizationGrant();
		assertEquals(GrantType.PASSWORD, pwdGrant.getType());
		assertEquals("johndoe", pwdGrant.getUsername());
		assertEquals("A3ddj3w", pwdGrant.getPassword().getValue());

		assertNull(tr.getScope());

		httpRequest = tr.toHTTPRequest();

		assertTrue(new URL("https://connect2id.com/token/").equals(httpRequest.getURL()));
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertNull(httpRequest.getAuthorization());
		assertEquals("password", httpRequest.getQueryParameters().get("grant_type"));
		assertEquals("johndoe", httpRequest.getQueryParameters().get("username"));
		assertEquals("A3ddj3w", httpRequest.getQueryParameters().get("password"));
		assertEquals(3, httpRequest.getQueryParameters().size());
	}


	public void testParsePasswordCredentialsGrantWithClientAuthentication()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		final String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);

		final String postBody = "grant_type=password&username=johndoe&password=A3ddj3w";

		httpRequest.setQuery(postBody);

		TokenRequest tr = TokenRequest.parse(httpRequest);

		assertTrue(new URI("https://connect2id.com/token/").equals(tr.getEndpointURI()));

		ClientSecretBasic authBasic = (ClientSecretBasic)tr.getClientAuthentication();
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, authBasic.getMethod());
		assertEquals("Basic " + authBasicString, authBasic.toHTTPAuthorizationHeader());
		assertEquals("s6BhdRkqt3", authBasic.getClientID().getValue());

		ResourceOwnerPasswordCredentialsGrant pwdGrant = (ResourceOwnerPasswordCredentialsGrant)tr.getAuthorizationGrant();
		assertEquals(GrantType.PASSWORD, pwdGrant.getType());
		assertEquals("johndoe", pwdGrant.getUsername());
		assertEquals("A3ddj3w", pwdGrant.getPassword().getValue());

		assertNull(tr.getScope());

		httpRequest = tr.toHTTPRequest();

		assertTrue(new URL("https://connect2id.com/token/").equals(httpRequest.getURL()));
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals("password", httpRequest.getQueryParameters().get("grant_type"));
		assertEquals("johndoe", httpRequest.getQueryParameters().get("username"));
		assertEquals("A3ddj3w", httpRequest.getQueryParameters().get("password"));
		assertEquals(3, httpRequest.getQueryParameters().size());
	}


	public void testParseClientCredentialsGrant()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		final String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);

		final String postBody = "grant_type=client_credentials";

		httpRequest.setQuery(postBody);

		TokenRequest tr = TokenRequest.parse(httpRequest);

		assertTrue(new URI("https://connect2id.com/token/").equals(tr.getEndpointURI()));

		ClientSecretBasic authBasic = (ClientSecretBasic)tr.getClientAuthentication();
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, authBasic.getMethod());
		assertEquals("Basic " + authBasicString, authBasic.toHTTPAuthorizationHeader());
		assertEquals("s6BhdRkqt3", authBasic.getClientID().getValue());

		ClientCredentialsGrant clientCredentialsGrant = (ClientCredentialsGrant)tr.getAuthorizationGrant();
		assertEquals(GrantType.CLIENT_CREDENTIALS, clientCredentialsGrant.getType());

		assertNull(tr.getScope());

		httpRequest = tr.toHTTPRequest();

		assertTrue(new URL("https://connect2id.com/token/").equals(httpRequest.getURL()));
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals(postBody, httpRequest.getQuery());
	}


	public void testParseClientCredentialsGrantMissingAuthentication()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		final String postBody = "grant_type=client_credentials";

		httpRequest.setQuery(postBody);

		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_CLIENT, e.getErrorObject());
		}
	}


	public void testSupportTokenRequestClientSecretPostSerialization()
		throws Exception {

		AuthorizationCode code = new AuthorizationCode();
		URI endpointUri = new URI("https://token.endpoint.uri/token");
		URI redirectUri = new URI("https://arbitrary.redirect.uri/");
		ClientID clientId = new ClientID("client");
		Secret secret = new Secret("secret");
		ClientSecretPost clientAuthentication = new ClientSecretPost(clientId,secret);
		AuthorizationGrant grant = new AuthorizationCodeGrant(code,redirectUri);
		TokenRequest request = new TokenRequest(endpointUri,clientAuthentication,grant);

		HTTPRequest httpRequest = request.toHTTPRequest();
		TokenRequest reconstructedRequest = TokenRequest.parse(httpRequest);
		
		assertEquals("client", reconstructedRequest.getClientAuthentication().getClientID().getValue());
		assertEquals("secret", ((ClientSecretPost) reconstructedRequest.getClientAuthentication()).getClientSecret().getValue());
		assertEquals(code, ((AuthorizationCodeGrant) reconstructedRequest.getAuthorizationGrant()).getAuthorizationCode());
	}


	// See issue 141
	public void testEmptyClientSecret()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://googleapis.com/oauth2/v3/token"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setQuery("code=0a2b49a9-985d-47cb-b36f-be9ed4927b4c&redirect_uri=https%3A%2F%2Fdevelopers.google.com%2Foauthplayground&client_id=google&client_secret=&scope=&grant_type=authorization_code");

		TokenRequest tokenRequest = TokenRequest.parse(httpRequest);

		assertEquals("https://googleapis.com/oauth2/v3/token", tokenRequest.getEndpointURI().toString());
		assertNull(tokenRequest.getClientAuthentication());
		AuthorizationGrant grant = tokenRequest.getAuthorizationGrant();
		assertTrue(grant instanceof AuthorizationCodeGrant);

		AuthorizationCodeGrant codeGrant = (AuthorizationCodeGrant)grant;
		assertEquals("0a2b49a9-985d-47cb-b36f-be9ed4927b4c", codeGrant.getAuthorizationCode().getValue());
		assertEquals("https://developers.google.com/oauthplayground", codeGrant.getRedirectionURI().toString());

		assertEquals("google", tokenRequest.getClientID().getValue());

		assertTrue(tokenRequest.getScope().isEmpty());
	}
}

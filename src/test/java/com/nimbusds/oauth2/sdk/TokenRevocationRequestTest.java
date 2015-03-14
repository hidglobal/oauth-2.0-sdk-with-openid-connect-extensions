package com.nimbusds.oauth2.sdk;


import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Tests the token revocation request.
 */
public class TokenRevocationRequestTest extends TestCase {


	public void testWithAccessToken()
		throws Exception {

		URI endpointURI = new URI("https://c2id.com/token/revoke");
		Token token = new BearerAccessToken();

		TokenRevocationRequest request = new TokenRevocationRequest(endpointURI, null, token);
		assertEquals(endpointURI, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(token, request.getToken());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(endpointURI.toURL().toString(), httpRequest.getURL().toString());
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertNull(httpRequest.getAuthorization());

		assertEquals(token.getValue(), httpRequest.getQueryParameters().get("token"));
		assertEquals("access_token", httpRequest.getQueryParameters().get("token_type_hint"));
		assertEquals(2, httpRequest.getQueryParameters().size());
	}


	public void testWithAccessTokenAndClientAuth()
		throws Exception {

		URI endpointURI = new URI("https://c2id.com/token/revoke");
		Token token = new BearerAccessToken();
		ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID("123"), new Secret("secret"));

		TokenRevocationRequest request = new TokenRevocationRequest(endpointURI, clientAuth, token);
		assertEquals(endpointURI, request.getEndpointURI());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertEquals(token, request.getToken());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(endpointURI.toURL().toString(), httpRequest.getURL().toString());
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());

		assertEquals(token.getValue(), httpRequest.getQueryParameters().get("token"));
		assertEquals("access_token", httpRequest.getQueryParameters().get("token_type_hint"));
		assertEquals(2, httpRequest.getQueryParameters().size());

		ClientSecretBasic basicAuth = ClientSecretBasic.parse(httpRequest.getAuthorization());
		assertEquals("123", basicAuth.getClientID().getValue());
		assertEquals("secret", basicAuth.getClientSecret().getValue());
	}


	public void testWithRefreshToken()
		throws Exception {

		URI endpointURI = new URI("https://c2id.com/token/revoke");
		Token token = new RefreshToken();

		TokenRevocationRequest request = new TokenRevocationRequest(endpointURI, null, token);
		assertEquals(endpointURI, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(token, request.getToken());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(endpointURI.toURL().toString(), httpRequest.getURL().toString());
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertNull(httpRequest.getAuthorization());

		assertEquals(token.getValue(), httpRequest.getQueryParameters().get("token"));
		assertEquals("refresh_token", httpRequest.getQueryParameters().get("token_type_hint"));
		assertEquals(2, httpRequest.getQueryParameters().size());
	}


	public void testWithRefreshTokenAndClientAuth()
		throws Exception {

		URI endpointURI = new URI("https://c2id.com/token/revoke");
		Token token = new RefreshToken();
		ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID("123"), new Secret("secret"));

		TokenRevocationRequest request = new TokenRevocationRequest(endpointURI, clientAuth, token);
		assertEquals(endpointURI, request.getEndpointURI());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertEquals(token, request.getToken());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(endpointURI.toURL().toString(), httpRequest.getURL().toString());
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());

		assertEquals(token.getValue(), httpRequest.getQueryParameters().get("token"));
		assertEquals("refresh_token", httpRequest.getQueryParameters().get("token_type_hint"));
		assertEquals(2, httpRequest.getQueryParameters().size());

		ClientSecretBasic basicAuth = ClientSecretBasic.parse(httpRequest.getAuthorization());
		assertEquals("123", basicAuth.getClientID().getValue());
		assertEquals("secret", basicAuth.getClientSecret().getValue());
	}


	public void testWithUnknownToken()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token/revoke"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		Map<String,String> queryParams = new HashMap<>();
		queryParams.put("token", "abc");
		httpRequest.setQuery(URLUtils.serializeParameters(queryParams));

		TokenRevocationRequest request = TokenRevocationRequest.parse(httpRequest);
		assertEquals("abc", request.getToken().getValue());
		assertFalse(request.getToken() instanceof AccessToken);
		assertFalse(request.getToken() instanceof RefreshToken);
	}
}

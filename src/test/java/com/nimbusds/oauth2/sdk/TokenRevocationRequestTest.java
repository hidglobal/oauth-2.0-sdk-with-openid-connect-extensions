package com.nimbusds.oauth2.sdk;


import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

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
import junit.framework.TestCase;


/**
 * Tests the token revocation request.
 */
public class TokenRevocationRequestTest extends TestCase {


	public void testWithAccessToken_publicClient()
		throws Exception {

		URI endpointURI = new URI("https://c2id.com/token/revoke");
		Token token = new BearerAccessToken();

		TokenRevocationRequest request = new TokenRevocationRequest(endpointURI, new ClientID("123"), token);
		assertEquals(endpointURI, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals(token, request.getToken());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(endpointURI.toURL().toString(), httpRequest.getURL().toString());
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertNull(httpRequest.getAuthorization());

		assertEquals(token.getValue(), httpRequest.getQueryParameters().get("token"));
		assertEquals("access_token", httpRequest.getQueryParameters().get("token_type_hint"));
		assertEquals("123", httpRequest.getQueryParameters().get("client_id"));
		assertEquals(3, httpRequest.getQueryParameters().size());

		request = TokenRevocationRequest.parse(httpRequest);
		assertEquals(endpointURI, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals(token.getValue(), request.getToken().getValue());
		assertTrue(request.getToken() instanceof AccessToken);
	}


	public void testWithAccessToken_confidentialClient()
		throws Exception {

		URI endpointURI = new URI("https://c2id.com/token/revoke");
		Token token = new BearerAccessToken();
		ClientSecretBasic clientAuth = new ClientSecretBasic(new ClientID("123"), new Secret("secret"));

		TokenRevocationRequest request = new TokenRevocationRequest(endpointURI, clientAuth, token);
		assertEquals(endpointURI, request.getEndpointURI());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertNull(request.getClientID());
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

		request = TokenRevocationRequest.parse(httpRequest);
		assertEquals(endpointURI, request.getEndpointURI());
		assertEquals(clientAuth.getClientID(), request.getClientAuthentication().getClientID());
		assertEquals(clientAuth.getClientSecret(), ((ClientSecretBasic)request.getClientAuthentication()).getClientSecret());
		assertNull(request.getClientID());
		assertEquals(token.getValue(), request.getToken().getValue());
		assertTrue(request.getToken() instanceof AccessToken);
	}


	public void testWithRefreshToken_publicClient()
		throws Exception {

		URI endpointURI = new URI("https://c2id.com/token/revoke");
		Token token = new RefreshToken();

		TokenRevocationRequest request = new TokenRevocationRequest(endpointURI, new ClientID("123"), token);
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
		assertEquals("123", httpRequest.getQueryParameters().get("client_id"));
		assertEquals(3, httpRequest.getQueryParameters().size());

		request = TokenRevocationRequest.parse(httpRequest);
		assertEquals(endpointURI, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals(token.getValue(), request.getToken().getValue());
		assertTrue(request.getToken() instanceof RefreshToken);
	}


	public void testWithRefreshToken_confidentialClient()
		throws Exception {

		URI endpointURI = new URI("https://c2id.com/token/revoke");
		Token token = new RefreshToken();
		ClientSecretBasic clientAuth = new ClientSecretBasic(new ClientID("123"), new Secret("secret"));

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

		request = TokenRevocationRequest.parse(httpRequest);
		assertEquals(endpointURI, request.getEndpointURI());
		assertEquals(clientAuth.getClientID(), request.getClientAuthentication().getClientID());
		assertEquals(clientAuth.getClientSecret(), ((ClientSecretBasic)request.getClientAuthentication()).getClientSecret());
		assertNull(request.getClientID());
		assertEquals(token.getValue(), request.getToken().getValue());
		assertTrue(request.getToken() instanceof RefreshToken);
	}


	public void testWithUnknownToken_publicClient()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token/revoke"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		Map<String,String> queryParams = new HashMap<>();
		queryParams.put("token", "abc");
		queryParams.put("client_id", "123");
		httpRequest.setQuery(URLUtils.serializeParameters(queryParams));

		TokenRevocationRequest request = TokenRevocationRequest.parse(httpRequest);
		assertEquals("abc", request.getToken().getValue());
		assertFalse(request.getToken() instanceof AccessToken);
		assertFalse(request.getToken() instanceof RefreshToken);
		assertNull(request.getClientAuthentication());
		assertEquals(new ClientID("123"), request.getClientID());
	}


	public void testWithUnknownToken_confidentialClient()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token/revoke"));
		httpRequest.setAuthorization(new ClientSecretBasic(new ClientID("123"), new Secret("secret")).toHTTPAuthorizationHeader());
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		Map<String,String> queryParams = new HashMap<>();
		queryParams.put("token", "abc");
		httpRequest.setQuery(URLUtils.serializeParameters(queryParams));

		TokenRevocationRequest request = TokenRevocationRequest.parse(httpRequest);
		assertEquals("abc", request.getToken().getValue());
		assertFalse(request.getToken() instanceof AccessToken);
		assertFalse(request.getToken() instanceof RefreshToken);
		assertEquals(new ClientID("123"), request.getClientAuthentication().getClientID());
		assertEquals(new Secret("secret"), ((ClientSecretBasic)request.getClientAuthentication()).getClientSecret());
		assertNull(request.getClientID());
	}


	public void testConstructorRequireClientAuthentication() {

		try {
			new TokenRevocationRequest(URI.create("https://c2id.com/token"), (ClientAuthentication)null, new BearerAccessToken());
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The client authentication must not be null", e.getMessage());
		}
	}


	public void testConstructorRequireClientID() {

		try {
			new TokenRevocationRequest(URI.create("https://c2id.com/token"), (ClientID) null, new BearerAccessToken());
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The client ID must not be null", e.getMessage());
		}
	}


	public void testParseMissingClientIdentification()
		throws MalformedURLException {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token/revoke"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		Map<String,String> queryParams = new HashMap<>();
		queryParams.put("token", "abc");
		httpRequest.setQuery(URLUtils.serializeParameters(queryParams));

		try {
			TokenRevocationRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid token revocation request: No client authentication or client_id parameter found", e.getMessage());
		}
	}
}

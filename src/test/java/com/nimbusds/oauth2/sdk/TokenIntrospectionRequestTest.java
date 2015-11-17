package com.nimbusds.oauth2.sdk;


import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Token;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;


/**
 * Tests the token introspection request.
 */
public class TokenIntrospectionRequestTest extends TestCase {
	

	public void testRFCExample_bearerTokenAuth()
		throws Exception {

		// POST /introspect HTTP/1.1
		// Host: server.example.com
		// Accept: application/json
		// Content-Type: application/x-www-form-urlencoded
		// Authorization: Bearer 23410913-abewfq.123483
		//
		// token=2YotnFZFEjr1zCsicMWpAA

		TokenIntrospectionRequest request = new TokenIntrospectionRequest(
			URI.create("https://server.example.com/introspect"),
			new BearerAccessToken("23410913-abewfq.123483"),
			new Token("2YotnFZFEjr1zCsicMWpAA") {
				@Override
				public Set<String> getParameterNames() {
					return null;
				}


				@Override
				public JSONObject toJSONObject() {
					return null;
				}


				@Override
				public boolean equals(Object object) {
					return false;
				}
			});

		assertEquals(URI.create("https://server.example.com/introspect"), request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(new BearerAccessToken("23410913-abewfq.123483"), request.getClientAuthorization());
		assertEquals("2YotnFZFEjr1zCsicMWpAA", request.getToken().getValue());
		assertTrue(request.getCustomParameters().isEmpty());

		// Output to HTTP request
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertEquals("Bearer 23410913-abewfq.123483", httpRequest.getAuthorization());
		assertEquals("token=2YotnFZFEjr1zCsicMWpAA", httpRequest.getQuery());

		// Parse from HTTP request
		request = TokenIntrospectionRequest.parse(httpRequest);

		assertEquals(URI.create("https://server.example.com/introspect"), request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(new BearerAccessToken("23410913-abewfq.123483"), request.getClientAuthorization());
		assertEquals("2YotnFZFEjr1zCsicMWpAA", request.getToken().getValue());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testRFCExample_clientSecretAuth()
		throws Exception {

		// POST /introspect HTTP/1.1
		// Host: server.example.com
		// Accept: application/json
		// Content-Type: application/x-www-form-urlencoded
		// Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
		//
		// token=mF_9.B5f-4.1JqM&token_type_hint=access_token

		TokenIntrospectionRequest request = new TokenIntrospectionRequest(
			URI.create("https://server.example.com/introspect"),
			ClientSecretBasic.parse("Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW"),
			new BearerAccessToken("mF_9.B5f-4.1JqM"));

		assertEquals(URI.create("https://server.example.com/introspect"), request.getEndpointURI());
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, request.getClientAuthentication().getMethod());
		assertEquals(new ClientID("s6BhdRkqt3"), request.getClientAuthentication().getClientID());
		assertEquals("gX1fBat3bV", ((ClientSecretBasic)request.getClientAuthentication()).getClientSecret().getValue());
		assertNull(request.getClientAuthorization());
		assertEquals("mF_9.B5f-4.1JqM", request.getToken().getValue());
		assertTrue(request.getToken() instanceof AccessToken);
		assertTrue(request.getCustomParameters().isEmpty());

		// Output to HTTP request
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertEquals("Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW", httpRequest.getAuthorization());
		assertEquals("mF_9.B5f-4.1JqM", httpRequest.getQueryParameters().get("token"));
		assertEquals("access_token", httpRequest.getQueryParameters().get("token_type_hint"));
		assertEquals(2, httpRequest.getQueryParameters().size());

		// Parse from HTTP request
		request = TokenIntrospectionRequest.parse(httpRequest);

		assertEquals(URI.create("https://server.example.com/introspect"), request.getEndpointURI());
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, request.getClientAuthentication().getMethod());
		assertEquals(new ClientID("s6BhdRkqt3"), request.getClientAuthentication().getClientID());
		assertEquals("gX1fBat3bV", ((ClientSecretBasic)request.getClientAuthentication()).getClientSecret().getValue());
		assertNull(request.getClientAuthorization());
		assertEquals("mF_9.B5f-4.1JqM", request.getToken().getValue());
		assertTrue(request.getToken() instanceof AccessToken);
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testUnauthenticated()
		throws Exception {

		URI endpoint = URI.create("https://c2id.com/token/inspect");
		BearerAccessToken accessToken = new BearerAccessToken("abc");

		TokenIntrospectionRequest request = new TokenIntrospectionRequest(endpoint, accessToken);

		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(accessToken, request.getToken());
		assertNull(request.getClientAuthentication());
		assertNull(request.getClientAuthorization());
		assertTrue(request.getCustomParameters().isEmpty());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertNull(httpRequest.getAuthorization());
		assertEquals(accessToken.getValue(), httpRequest.getQueryParameters().get("token"));
		assertEquals("access_token", httpRequest.getQueryParameters().get("token_type_hint"));
		assertEquals(2, httpRequest.getQueryParameters().size());

		request = TokenIntrospectionRequest.parse(httpRequest);

		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(accessToken.getValue(), request.getToken().getValue());
		assertTrue(request.getToken() instanceof AccessToken);
		assertNull(request.getClientAuthentication());
		assertNull(request.getClientAuthorization());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testUnauthenticated_customParams()
		throws Exception {

		URI endpoint = URI.create("https://c2id.com/token/inspect");
		BearerAccessToken accessToken = new BearerAccessToken("abc");
		Map<String,String> customParams = new HashMap<>();
		customParams.put("ip", "10.20.30.40");

		TokenIntrospectionRequest request = new TokenIntrospectionRequest(endpoint, accessToken, customParams);

		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(accessToken, request.getToken());
		assertNull(request.getClientAuthentication());
		assertNull(request.getClientAuthorization());
		assertEquals("10.20.30.40", request.getCustomParameters().get("ip"));
		assertEquals(1, request.getCustomParameters().size());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertNull(httpRequest.getAuthorization());
		assertEquals(accessToken.getValue(), httpRequest.getQueryParameters().get("token"));
		assertEquals("access_token", httpRequest.getQueryParameters().get("token_type_hint"));
		assertEquals("10.20.30.40", httpRequest.getQueryParameters().get("ip"));
		assertEquals(3, httpRequest.getQueryParameters().size());

		request = TokenIntrospectionRequest.parse(httpRequest);

		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(accessToken.getValue(), request.getToken().getValue());
		assertTrue(request.getToken() instanceof AccessToken);
		assertNull(request.getClientAuthentication());
		assertNull(request.getClientAuthorization());
		assertEquals("10.20.30.40", request.getCustomParameters().get("ip"));
		assertEquals(1, request.getCustomParameters().size());
	}


	public void testClientSecretAuthenticated_customParams()
		throws Exception {

		URI endpoint = URI.create("https://c2id.com/token/inspect");
		ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID("123"), new Secret("secret"));
		BearerAccessToken accessToken = new BearerAccessToken("abc");
		Map<String,String> customParams = new HashMap<>();
		customParams.put("ip", "10.20.30.40");

		TokenIntrospectionRequest request = new TokenIntrospectionRequest(endpoint, clientAuth, accessToken, customParams);

		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(accessToken, request.getToken());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertNull(request.getClientAuthorization());
		assertEquals("10.20.30.40", request.getCustomParameters().get("ip"));
		assertEquals(1, request.getCustomParameters().size());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertEquals(new ClientID("123"), ClientSecretBasic.parse(httpRequest.getAuthorization()).getClientID());
		assertEquals(new Secret("secret"), ClientSecretBasic.parse(httpRequest.getAuthorization()).getClientSecret());
		assertEquals(accessToken.getValue(), httpRequest.getQueryParameters().get("token"));
		assertEquals("access_token", httpRequest.getQueryParameters().get("token_type_hint"));
		assertEquals("10.20.30.40", httpRequest.getQueryParameters().get("ip"));
		assertEquals(3, httpRequest.getQueryParameters().size());

		request = TokenIntrospectionRequest.parse(httpRequest);

		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(accessToken.getValue(), request.getToken().getValue());
		assertTrue(request.getToken() instanceof AccessToken);
		assertEquals(new ClientID("123"), request.getClientAuthentication().getClientID());
		assertEquals(new Secret("secret"), ((ClientSecretBasic)request.getClientAuthentication()).getClientSecret());
		assertNull(request.getClientAuthorization());
		assertEquals("10.20.30.40", request.getCustomParameters().get("ip"));
		assertEquals(1, request.getCustomParameters().size());
	}


	public void testBearerTokenAuthorized_customParams()
		throws Exception {

		URI endpoint = URI.create("https://c2id.com/token/inspect");
		BearerAccessToken clientAuthz = new BearerAccessToken("xyz");
		BearerAccessToken accessToken = new BearerAccessToken("abc");
		Map<String,String> customParams = new HashMap<>();
		customParams.put("ip", "10.20.30.40");

		TokenIntrospectionRequest request = new TokenIntrospectionRequest(endpoint, clientAuthz, accessToken, customParams);

		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(accessToken, request.getToken());
		assertNull(request.getClientAuthentication());
		assertEquals(clientAuthz, request.getClientAuthorization());
		assertEquals("10.20.30.40", request.getCustomParameters().get("ip"));
		assertEquals(1, request.getCustomParameters().size());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertEquals(clientAuthz.toAuthorizationHeader(), httpRequest.getAuthorization());
		assertEquals(accessToken.getValue(), httpRequest.getQueryParameters().get("token"));
		assertEquals("access_token", httpRequest.getQueryParameters().get("token_type_hint"));
		assertEquals("10.20.30.40", httpRequest.getQueryParameters().get("ip"));
		assertEquals(3, httpRequest.getQueryParameters().size());

		request = TokenIntrospectionRequest.parse(httpRequest);

		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(accessToken.getValue(), request.getToken().getValue());
		assertNull(request.getClientAuthentication());
		assertEquals(clientAuthz, request.getClientAuthorization());
		assertEquals("10.20.30.40", request.getCustomParameters().get("ip"));
		assertEquals(1, request.getCustomParameters().size());
	}
}

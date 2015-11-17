package com.nimbusds.oauth2.sdk;


import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.util.DateUtils;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;


/**
 * Tests the token introspection success response class.
 */
public class TokenIntrospectionSuccessResponseTest extends TestCase {
	

	public void testExample()
		throws Exception {
		
		HTTPResponse httpResponse = new HTTPResponse(200);
		httpResponse.setContentType("application/json");
		String json = 
			"{\n" +
			" \"active\": true,\n" +
			" \"client_id\": \"l238j323ds-23ij4\",\n" +
			" \"username\": \"jdoe\",\n" +
			" \"scope\": \"read write dolphin\",\n" +
			" \"sub\": \"Z5O3upPC88QrAjx00dis\",\n" +
			" \"aud\": \"https://protected.example.net/resource\",\n" +
			" \"iss\": \"https://server.example.com/\",\n" +
			" \"exp\": 1419356238,\n" +
			" \"iat\": 1419350238,\n" +
			" \"extension_field\": \"twenty-seven\"\n" +
			"}";
		httpResponse.setContent(json);

		TokenIntrospectionSuccessResponse response = TokenIntrospectionSuccessResponse.parse(httpResponse);
		assertTrue(response.indicatesSuccess());
		assertTrue(response.isActive());
		assertEquals(new ClientID("l238j323ds-23ij4"), response.getClientID());
		assertEquals("jdoe", response.getUsername());
		assertEquals(Scope.parse("read write dolphin"), response.getScope());
		assertEquals(new Subject("Z5O3upPC88QrAjx00dis"), response.getSubject());
		assertEquals(new Audience("https://protected.example.net/resource"), response.getAudience().get(0));
		assertEquals(1, response.getAudience().size());
		assertEquals(new Issuer("https://server.example.com/"), response.getIssuer());
		assertEquals(DateUtils.fromSecondsSinceEpoch(1419356238l), response.getExpirationTime());
		assertEquals(DateUtils.fromSecondsSinceEpoch(1419350238l), response.getIssueTime());
		assertEquals("twenty-seven", response.toJSONObject().get("extension_field"));

		httpResponse = response.toHTTPResponse();

		response = TokenIntrospectionSuccessResponse.parse(httpResponse);
		assertTrue(response.indicatesSuccess());
		assertTrue(response.isActive());
		assertEquals(new ClientID("l238j323ds-23ij4"), response.getClientID());
		assertEquals("jdoe", response.getUsername());
		assertEquals(Scope.parse("read write dolphin"), response.getScope());
		assertEquals(new Subject("Z5O3upPC88QrAjx00dis"), response.getSubject());
		assertEquals(new Audience("https://protected.example.net/resource"), response.getAudience().get(0));
		assertEquals(1, response.getAudience().size());
		assertEquals(new Issuer("https://server.example.com/"), response.getIssuer());
		assertEquals(DateUtils.fromSecondsSinceEpoch(1419356238l), response.getExpirationTime());
		assertEquals(DateUtils.fromSecondsSinceEpoch(1419350238l), response.getIssueTime());
		assertEquals("twenty-seven", response.toJSONObject().get("extension_field"));
	}


	public void testBuilderMinimal_active()
		throws Exception {

		TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(true)
			.build();

		assertTrue(response.isActive());
		assertNull(response.getScope());
		assertNull(response.getClientID());
		assertNull(response.getUsername());
		assertNull(response.getTokenType());
		assertNull(response.getExpirationTime());
		assertNull(response.getIssueTime());
		assertNull(response.getNotBeforeTime());
		assertNull(response.getSubject());
		assertNull(response.getAudience());
		assertNull(response.getIssuer());
		assertNull(response.getJWTID());

		JSONObject jsonObject = response.toJSONObject();
		assertTrue((Boolean) jsonObject.get("active"));
		assertEquals(1, jsonObject.size());

		HTTPResponse httpResponse = response.toHTTPResponse();

		assertEquals(200, httpResponse.getStatusCode());
		assertEquals(CommonContentTypes.APPLICATION_JSON.getBaseType(), httpResponse.getContentType().getBaseType());
		jsonObject = httpResponse.getContentAsJSONObject();
		assertTrue((Boolean) jsonObject.get("active"));
		assertEquals(1, jsonObject.size());

		response = TokenIntrospectionSuccessResponse.parse(httpResponse);

		assertTrue(response.isActive());
		assertNull(response.getScope());
		assertNull(response.getClientID());
		assertNull(response.getUsername());
		assertNull(response.getTokenType());
		assertNull(response.getExpirationTime());
		assertNull(response.getIssueTime());
		assertNull(response.getNotBeforeTime());
		assertNull(response.getSubject());
		assertNull(response.getAudience());
		assertNull(response.getIssuer());
		assertNull(response.getJWTID());
	}


	public void testBuilderMinimal_inactive()
		throws Exception {

		TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(false)
			.build();

		assertFalse(response.isActive());
		assertNull(response.getScope());
		assertNull(response.getClientID());
		assertNull(response.getUsername());
		assertNull(response.getTokenType());
		assertNull(response.getExpirationTime());
		assertNull(response.getIssueTime());
		assertNull(response.getNotBeforeTime());
		assertNull(response.getSubject());
		assertNull(response.getAudience());
		assertNull(response.getIssuer());
		assertNull(response.getJWTID());

		JSONObject jsonObject = response.toJSONObject();
		assertFalse((Boolean) jsonObject.get("active"));
		assertEquals(1, jsonObject.size());

		HTTPResponse httpResponse = response.toHTTPResponse();

		assertEquals(200, httpResponse.getStatusCode());
		assertEquals(CommonContentTypes.APPLICATION_JSON.getBaseType(), httpResponse.getContentType().getBaseType());
		jsonObject = httpResponse.getContentAsJSONObject();
		assertFalse((Boolean) jsonObject.get("active"));
		assertEquals(1, jsonObject.size());

		response = TokenIntrospectionSuccessResponse.parse(httpResponse);

		assertFalse(response.isActive());
		assertNull(response.getScope());
		assertNull(response.getClientID());
		assertNull(response.getUsername());
		assertNull(response.getTokenType());
		assertNull(response.getExpirationTime());
		assertNull(response.getIssueTime());
		assertNull(response.getNotBeforeTime());
		assertNull(response.getSubject());
		assertNull(response.getAudience());
		assertNull(response.getIssuer());
		assertNull(response.getJWTID());
		assertNull(response.getScope());
		assertNull(response.getClientID());
		assertNull(response.getUsername());
		assertNull(response.getTokenType());
		assertNull(response.getExpirationTime());
		assertNull(response.getIssueTime());
		assertNull(response.getNotBeforeTime());
		assertNull(response.getSubject());
		assertNull(response.getAudience());
		assertNull(response.getIssuer());
		assertNull(response.getJWTID());
	}


	public void testBuilder_complete()
		throws Exception {

		TokenIntrospectionSuccessResponse response = new TokenIntrospectionSuccessResponse.Builder(true)
			.scope(Scope.parse("read write"))
			.clientID(new ClientID("123"))
			.username("alice")
			.tokenType(AccessTokenType.BEARER)
			.expirationTime(DateUtils.fromSecondsSinceEpoch(102030L))
			.issueTime(DateUtils.fromSecondsSinceEpoch(203040L))
			.notBeforeTime(DateUtils.fromSecondsSinceEpoch(304050L))
			.subject(new Subject("alice.wonderland"))
			.audience(Audience.create("456", "789"))
			.issuer(new Issuer("https://c2id.com"))
			.jwtID(new JWTID("xyz"))
			.parameter("ip", "10.20.30.40")
			.build();

		assertTrue(response.isActive());
		assertEquals(Scope.parse("read write"), response.getScope());
		assertEquals(new ClientID("123"), response.getClientID());
		assertEquals("alice", response.getUsername());
		assertEquals(AccessTokenType.BEARER, response.getTokenType());
		assertEquals(DateUtils.fromSecondsSinceEpoch(102030L), response.getExpirationTime());
		assertEquals(DateUtils.fromSecondsSinceEpoch(203040L), response.getIssueTime());
		assertEquals(DateUtils.fromSecondsSinceEpoch(304050L), response.getNotBeforeTime());
		assertEquals(new Subject("alice.wonderland"), response.getSubject());
		assertEquals(Audience.create("456", "789"), response.getAudience());
		assertEquals(new Issuer("https://c2id.com"), response.getIssuer());
		assertEquals(new JWTID("xyz"), response.getJWTID());
		assertEquals("10.20.30.40", response.toJSONObject().get("ip"));

		assertEquals(13, response.toJSONObject().size());

		HTTPResponse httpResponse = response.toHTTPResponse();

		assertEquals(200, httpResponse.getStatusCode());
		assertEquals("application/json; charset=UTF-8", httpResponse.getContentType().toString());

		response = TokenIntrospectionSuccessResponse.parse(httpResponse);

		assertTrue(response.isActive());
		assertEquals(Scope.parse("read write"), response.getScope());
		assertEquals(new ClientID("123"), response.getClientID());
		assertEquals("alice", response.getUsername());
		assertEquals(AccessTokenType.BEARER, response.getTokenType());
		assertEquals(DateUtils.fromSecondsSinceEpoch(102030L), response.getExpirationTime());
		assertEquals(DateUtils.fromSecondsSinceEpoch(203040L), response.getIssueTime());
		assertEquals(DateUtils.fromSecondsSinceEpoch(304050L), response.getNotBeforeTime());
		assertEquals(new Subject("alice.wonderland"), response.getSubject());
		assertEquals(Audience.create("456", "789"), response.getAudience());
		assertEquals(new Issuer("https://c2id.com"), response.getIssuer());
		assertEquals(new JWTID("xyz"), response.getJWTID());
		assertEquals("10.20.30.40", response.toJSONObject().get("ip"));

		assertEquals(13, response.toJSONObject().size());
	}
}

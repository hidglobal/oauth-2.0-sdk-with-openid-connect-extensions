package com.nimbusds.oauth2.sdk.client;


import com.nimbusds.langtag.LangTag;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import java.net.URL;
import org.junit.Test;
import static org.junit.Assert.*;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import java.util.Set;


/**
 * Tests the client update request class.
 */
public class ClientUpdateRequestTest {
	
	@Test
	public void testParse() throws Exception {
		
		URL regURI = new URL("https://server.example.com/register/s6BhdRkqt3");
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.PUT, regURI);
		httpRequest.setAuthorization("Bearer reg-23410913-abewfq.123483");
		httpRequest.setContentType(CommonContentTypes.APPLICATION_JSON);

		String json = "{\"client_id\":\"s6BhdRkqt3\","
			+ "    \"client_secret\": \"cf136dc3c1fc93f31185e5885805d\","
			+ "    \"redirect_uris\":[\"https://client.example.org/callback\",\"https://client.example.org/alt\"],"
			+ "    \"scope\": \"read write dolphin\","
			+ "    \"grant_types\": [\"authorization_code\", \"refresh_token\"],"
			+ "    \"token_endpoint_auth_method\": \"client_secret_basic\","
			+ "    \"jwks_uri\": \"https://client.example.org/my_public_keys.jwks\","
			+ "    \"client_name\":\"My New Example\","
			+ "    \"client_name#fr\":\"Mon Nouvel Exemple\","
			+ "    \"logo_uri\":\"https://client.example.org/newlogo.png\","
			+ "    \"logo_uri#fr\":\"https://client.example.org/fr/newlogo.png\""
			+ "   }";

		httpRequest.setQuery(json);
		
		ClientUpdateRequest request = ClientUpdateRequest.parse(httpRequest);
		
		assertEquals(regURI, request.getURI());
		
		assertEquals("reg-23410913-abewfq.123483", request.getAccessToken().getValue());
		
		assertEquals("s6BhdRkqt3", request.getClientID().getValue());
		
		assertEquals("cf136dc3c1fc93f31185e5885805d", request.getClientSecret().getValue());
		
		ClientMetadata metadata = request.getClientMetadata();
		
		Set<URL> redirectURIs = metadata.getRedirectionURIs();
		assertTrue(redirectURIs.contains(new URL("https://client.example.org/callback")));
		assertTrue(redirectURIs.contains(new URL("https://client.example.org/alt")));
		assertEquals(2, redirectURIs.size());
		
		assertEquals(Scope.parse("read write dolphin"), metadata.getScope());
		
		Set<GrantType> grantTypes = metadata.getGrantTypes();
		assertTrue(grantTypes.contains(GrantType.AUTHORIZATION_CODE));
		assertTrue(grantTypes.contains(GrantType.REFRESH_TOKEN));
		assertEquals(2, grantTypes.size());
		
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, metadata.getTokenEndpointAuthMethod());
		
		assertEquals(new URL("https://client.example.org/my_public_keys.jwks"), metadata.getJWKSetURI());
		
		assertEquals("My New Example", metadata.getName());
		assertEquals("My New Example", metadata.getName(null));
		
		assertEquals("Mon Nouvel Exemple", metadata.getName(LangTag.parse("fr")));
		
		assertEquals(2, metadata.getNameEntries().size());
		
		assertEquals(new URL("https://client.example.org/newlogo.png"), metadata.getLogoURI());
		assertEquals(new URL("https://client.example.org/newlogo.png"), metadata.getLogoURI(null));
		
		assertEquals(new URL("https://client.example.org/fr/newlogo.png"), metadata.getLogoURI(LangTag.parse("fr")));
		
		assertEquals(2, metadata.getLogoURIEntries().size());
	}
}
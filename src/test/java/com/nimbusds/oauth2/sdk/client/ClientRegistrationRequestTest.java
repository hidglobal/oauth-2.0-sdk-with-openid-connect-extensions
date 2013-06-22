package com.nimbusds.oauth2.sdk.client;


import com.nimbusds.langtag.LangTag;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import java.net.URL;
import java.util.Set;
import org.junit.Test;
import static org.junit.Assert.*;


/**
 * Tests the client registration request class.
 * 
 * @author Vladimir Dzhuvinov
 */
public class ClientRegistrationRequestTest {
	
	
	@Test
	public void testParse() throws Exception {
		
		URL uri = new URL("https://server.example.com/register/");
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, uri);
		httpRequest.setContentType(CommonContentTypes.APPLICATION_JSON);
		
		String json = "{"
			+ "    \"redirect_uris\":[\"https://client.example.org/callback\","
			+ "       \"https://client.example.org/callback2\"],"
			+ "    \"client_name\":\"My Example Client\","
			+ "    \"client_name#ja-Jpan-JP\":\"\\u30AF\\u30E9\\u30A4\\u30A2\\u30F3\\u30C8\\u540D\","
			+ "    \"token_endpoint_auth_method\":\"client_secret_basic\","
			+ "    \"scope\":\"read write dolphin\","
			+ "    \"logo_uri\":\"https://client.example.org/logo.png\","
			+ "    \"jwks_uri\":\"https://client.example.org/my_public_keys.jwks\""
			+ "   }";
		
		
		httpRequest.setQuery(json);
		
		ClientRegistrationRequest request = ClientRegistrationRequest.parse(httpRequest);
		
		assertNull(request.getAccessToken());
		
		ClientMetadata metadata = request.getClientMetadata();
		
		Set<URL> redirectURIs = metadata.getRedirectURIs();
		assertTrue(redirectURIs.contains(new URL("https://client.example.org/callback")));
		assertTrue(redirectURIs.contains(new URL("https://client.example.org/callback2")));
		assertEquals(2, redirectURIs.size());
		
		assertEquals("My Example Client", metadata.getName());
		assertEquals("\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D", metadata.getName(LangTag.parse("ja-Jpan-JP")));
		
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, metadata.getTokenEndpointAuthMethod());
		
		assertEquals(Scope.parse("read write dolphin"), metadata.getScope());
		
		assertEquals(new URL("https://client.example.org/logo.png"), metadata.getLogoURI());
		
		assertEquals(new URL("https://client.example.org/my_public_keys.jwks"), metadata.getJWKSetURI());
	}
}
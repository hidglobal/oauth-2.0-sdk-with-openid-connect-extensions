package com.nimbusds.openid.connect.sdk.rp;


import java.net.URL;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import junit.framework.TestCase;


/**
 * Tests the OIDC client update request.
 */
public class OIDCClientUpdateRequestTest extends TestCase {


	public void testCycle()
		throws Exception {

		URL uri = new URL("https://c2id.com/client-reg/123");
		ClientID clientID = new ClientID("123");
		BearerAccessToken accessToken = new BearerAccessToken();
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setRedirectionURI(new URL("https://client.com/cb"));
		metadata.setName("My app");
		metadata.applyDefaults();
		Secret secret = new Secret();

		OIDCClientUpdateRequest request = new OIDCClientUpdateRequest(
			uri,
			clientID,
			accessToken,
			metadata,
			secret);

		assertEquals(uri, request.getURI());
		assertEquals(clientID, request.getClientID());
		assertEquals(accessToken, request.getAccessToken());
		assertEquals(metadata, request.getOIDCClientMetadata());
		assertEquals(metadata, request.getClientMetadata());
		assertEquals(secret, request.getClientSecret());


		HTTPRequest httpRequest = request.toHTTPRequest();

		request = OIDCClientUpdateRequest.parse(httpRequest);

		assertEquals(uri.toString(), request.getURI().toString());
		assertEquals(clientID.getValue(), request.getClientID().getValue());
		assertEquals(accessToken.getValue(), request.getAccessToken().getValue());
		assertEquals("https://client.com/cb", request.getClientMetadata().getRedirectionURIs().iterator().next().toString());
		assertEquals("My app", request.getClientMetadata().getName());
		assertEquals(secret.getValue(), request.getClientSecret().getValue());
	}

}

package com.nimbusds.openid.connect.sdk.rp;


import java.net.URL;
import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


/**
 * Tests the OIDC client information response.
 */
public class OIDCClientInformationResponseTest extends TestCase {


	public void testCycle()
		throws Exception {

		ClientID id = new ClientID("123");
		URL url = new URL("https://c2id.com/client-reg/123");
		BearerAccessToken accessToken = new BearerAccessToken();
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setRedirectionURI(new URL("https://client.com/cb"));
		metadata.applyDefaults();
		Secret secret = new Secret();
		Date issueDate = new Date(new Date().getTime() / 1000 * 1000);

		OIDCClientInformation info = new OIDCClientInformation(
			id, url, accessToken, metadata, secret, issueDate);

		OIDCClientInformationResponse response = new OIDCClientInformationResponse(info);

		assertEquals(info, response.getOIDCClientInformation());
		assertEquals(info, response.getClientInformation());

		HTTPResponse httpResponse = response.toHTTPResponse();

		response = OIDCClientInformationResponse.parse(httpResponse);

		assertEquals(id.getValue(), response.getClientInformation().getID().getValue());
		assertEquals(url.toString(), response.getClientInformation().getRegistrationURI().toString());
		assertEquals(accessToken.getValue(), response.getClientInformation().getRegistrationAccessToken().getValue());
		assertEquals("https://client.com/cb", response.getClientInformation().getClientMetadata().getRedirectionURIs().iterator().next().toString());
		assertEquals(secret.getValue(), response.getClientInformation().getSecret().getValue());
		assertEquals(issueDate, response.getClientInformation().getIssueDate());
	}
}

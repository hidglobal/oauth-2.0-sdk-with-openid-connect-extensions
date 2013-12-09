package com.nimbusds.openid.connect.sdk.rp;


import java.net.URL;

import com.nimbusds.oauth2.sdk.client.ClientRegistrationErrorResponse;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import junit.framework.TestCase;


/**
 * Tests the OIDC client registration response parser.
 */
public class OIDCClientRegistrationResponseParserTest extends TestCase {


	public void testParseSuccess()
		throws Exception {

		ClientID id = new ClientID("123");
		URL regURL = new URL("https://c2id.com/client-reg/123");
		BearerAccessToken accessToken = new BearerAccessToken();
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setRedirectionURI(new URL("https://client.com/cb"));
		metadata.setName("My app");
		metadata.applyDefaults();

		OIDCClientInformation clientInfo = new OIDCClientInformation(id, regURL, accessToken, metadata, null, null);

		OIDCClientInformationResponse response = new OIDCClientInformationResponse(clientInfo);

		HTTPResponse httpResponse = response.toHTTPResponse();

		ClientRegistrationResponse regResponse = OIDCClientRegistrationResponseParser.parse(httpResponse);

		response = (OIDCClientInformationResponse)regResponse;

		assertEquals(id, response.getOIDCClientInformation().getID());
		assertEquals(regURL, response.getOIDCClientInformation().getRegistrationURI());
		assertEquals(accessToken.getValue(), response.getOIDCClientInformation().getRegistrationAccessToken().getValue());
		assertEquals("My app", response.getOIDCClientInformation().getClientMetadata().getName());
		assertNull(response.getOIDCClientInformation().getSecret());
		assertNull(response.getOIDCClientInformation().getIssueDate());
	}


	public void testParseError()
		throws Exception {

		ClientRegistrationErrorResponse response = new ClientRegistrationErrorResponse(BearerTokenError.INVALID_TOKEN);

		HTTPResponse httpResponse = response.toHTTPResponse();

		ClientRegistrationResponse regResponse = OIDCClientRegistrationResponseParser.parse(httpResponse);

		response = (ClientRegistrationErrorResponse)regResponse;
		assertEquals(BearerTokenError.INVALID_TOKEN.getCode(), response.getErrorObject().getCode());
	}
}

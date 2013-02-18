package com.nimbusds.openid.connect.sdk;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SuccessResponse;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import com.nimbusds.openid.connect.sdk.rp.Client;



/**
 * OpenID Connect client details response. This class is immutable.
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 * Cache-Control: no-store
 *
 * {
 *  "client_id"                       : "s6BhdRkqt3",
 *  "client_secret"                   : "ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk",
 *  "expires_at"                      : 1577858400,
 *  "registration_access_token"       : "this.is.an.access.token.value.ffx83",
 *  "registration_access_url"         : "https://server.example.com/connect/register",
 *  "token_endpoint_auth_method"      : "client_secret_basic",
 *  "application_type"                : "web",
 *  "redirect_uris"                   : [ "https://client.example.org/callback"
 *                                        "https://client.example.org/callback2" ],
 *  "client_name"                     : "My Example",
 *  "client_name#ja-Jpan-JP"          : "クライアント名",
 *  "logo_url"                        : "https://client.example.org/logo.png",
 *  "subject_type"                    : "pairwise",
 *  "sector_identifier_url"           : "https://othercompany.com/file_of_redirect_uris.json",
 *  "x509_url"                        : "https://client.example.org/certs.x509",
 *  "jwk_url"                         : "https://client.example.org/my_rsa_public_key.jwk",
 *  "userinfo_encrypted_response_alg" : "RSA1_5",
 *  "userinfo_encrypted_response_enc" : "A128CBC+HS256"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 3.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-02-18)
 */
@Immutable
public class OIDCClientDetailsResponse 
	extends OIDCClientRegistrationResponse
	implements SuccessResponse {


	/**
	 * The client details.
	 */
	private Client client;


	/**
	 * Creates a new OpenID Connect client details response.
	 *
	 * @param client The client details. Must not be {@code null}.
	 */
	public OIDCClientDetailsResponse(final Client client) {

		if (client == null)
			throw new IllegalArgumentException("The client details must not be null");

		this.client = client;
	}


	/**
	 * Gets the associated client details.
	 *
	 * @return The client details.
	 */
	public Client getClientDetails() {

		return client;
	}


	@Override
	public HTTPResponse toHTTPResponse() {
	
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);

		httpResponse.setContent(client.toJSONObject().toString());
	
		return httpResponse;
	}


	/**
	 * Parses an OpenID Connect client details response from the specified 
	 * HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The OpenID Connect client details response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an 
	 *                        OpenID Connect client details response.
	 */
	public static OIDCClientDetailsResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		httpResponse.ensureStatusCode(HTTPResponse.SC_OK);

		Client client = Client.parse(httpResponse.getContentAsJSONObject());

		return new OIDCClientDetailsResponse(client);
	}
}
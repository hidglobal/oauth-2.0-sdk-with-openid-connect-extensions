package com.nimbusds.openid.connect.sdk;


import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SuccessResponse;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import com.nimbusds.openid.connect.sdk.rp.Client;


/**
 * OpenID Connect client update success response.
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 * Cache-Control: no-store
 *
 * {
 *   "client_id"                       : "s6BhdRkqt3",
 *   "token_endpoint_auth_method"      : "client_secret_basic",
 *   "application_type"                : "web",
 *   "redirect_uris"                   : "https://client.example.org/callback
 *                                        https://client.example.org/callback2",
 *   "client_name"                     : "My Client",
 *   "client_name#ja-Jpan-JP"          : "ワタシ用の例",
 *   "logo_url"                        : "https://client.example.org/logo.png",
 *   "subject_type"                    : "pairwise",
 *   "sector_identifier_url"           : "https://othercompany.com/file_of_redirect_uris.json"
 *   "jwk_url"                         : "https://client.example.org/my_rsa_public_key.jwk",
 *   "userinfo_encrypted_response_alg" : "RSA1_5",
 *   "userinfo_encrypted_response_enc" : "A128CBC+HS256"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 2.2.3.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-29)
 */
public class ClientUpdateSuccessResponse 
	extends ClientUpdateResponse
	implements SuccessResponse {


	/**
	 * The client details.
	 */
	private final Client client;


	/**
	 * Creates a new OpenID Connect client update success response.
	 *
	 * @param client The client details. Must not be {@code null}.
	 */
	public ClientUpdateSuccessResponse(final Client client) {

		if (client == null)
			throw new IllegalArgumentException("The client details must not be null");

		this.client = client;
	}


	/**
	 * Gets the client details.
	 *
	 * @return The client details.
	 */
	public Client getClientDetails() {

		return client;
	}


	public JSONObject toJSONObject() {

		return client.toJSONObject();
	}


	/**
	 * Parses an OpenID Connect client update success response from the
	 * specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The OpenID Connect client update success response.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        OpenID Connect client update success 
	 *                        response.
	 */
	public static ClientUpdateSuccessResponse parse(final JSONObject jsonObject)
		throws ParseException {

		Client client = Client.parse(jsonObject);

		return new ClientUpdateSuccessResponse(client);
	}


	/**
	 * Parses an OpenID Connect client update success response from the
	 * specified HTTP response.
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @return The OpenID Connect client update success response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an
	 *                        OpenID Connect client update success 
	 *                        response.
	 */
	public static ClientUpdateSuccessResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		httpResponse.ensureStatusCode(HTTPResponse.SC_OK);

		httpResponse.ensureContentType(CommonContentTypes.APPLICATION_JSON);

		JSONObject jsonObject = httpResponse.getContentAsJSONObject();

		return parse(jsonObject);
	}
}
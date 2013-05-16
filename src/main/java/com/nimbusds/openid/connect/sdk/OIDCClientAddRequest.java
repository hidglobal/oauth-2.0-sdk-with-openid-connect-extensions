package com.nimbusds.openid.connect.sdk;


import java.net.URL;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.openid.connect.sdk.rp.Client;


/**
 * OpenID Connect client add (register) request.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * POST /connect/register HTTP/1.1
 * Content-Type: application/json
 * Host: server.example.com
 * Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJ ...
 *
 * {
 *  "application_type"                : "web",
 *  "redirect_uris"                   : [ "https://client.example.org/callback", 
 *                                        "https://client.example.org/callback2" ],
 *  "client_name"                     : "My Example",
 *  "client_name#ja-Jpan-JP"          : "クライアント名",
 *  "logo_url"                        : "https://client.example.org/logo.png",
 *  "subject_type"                    : "pairwise",
 *  "sector_identifier_url"           : "https://othercompany.com/file_of_redirect_uris.json",
 *  "token_endpoint_auth_method"      : "client_secret_basic",
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
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 3.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
public class OIDCClientAddRequest extends OIDCClientRegistrationRequest {


	/**
	 * The client details.
	 */
	private final Client client;


	/**
	 * Creates a new OpenID Connect client add (register) request.
	 *
	 * @param client The client details. Must not be {@code null} and must
	 *               specify one or more redirect URIs.
	 */
	public OIDCClientAddRequest(final Client client) {

		super();

		if (client.getRedirectURIs() == null || client.getRedirectURIs().isEmpty())
			throw new IllegalArgumentException("The client details must specify one or more redirect URIs");

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
	public HTTPRequest toHTTPRequest(final URL url) {
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, url);

		if (getAccessToken() != null)
			httpRequest.setAuthorization(getAccessToken().toAuthorizationHeader());

		httpRequest.setContentType(CommonContentTypes.APPLICATION_JSON);

		httpRequest.setQuery(client.toJSONObject().toString());

		return httpRequest;
	}


	/**
	 * Parses an OpenID Connect client add (register) request from the
	 * specified HTTP POST request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The client add (register) request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        client register request.
	 */
	public static OIDCClientAddRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		httpRequest.ensureMethod(HTTPRequest.Method.POST);

		JSONObject jsonObject = httpRequest.getQueryAsJSONObject();

		Client client = Client.parse(jsonObject);

		if (client.getRedirectURIs() == null ||
		    client.getRedirectURIs().isEmpty())
			throw new ParseException("The client details must specify one or more redirect URIs");

		OIDCClientAddRequest req = new OIDCClientAddRequest(client);

		String authzHeaderValue = httpRequest.getAuthorization();

		if (StringUtils.isDefined(authzHeaderValue))
			req.setAccessToken(BearerAccessToken.parse(authzHeaderValue));

		return req;
	}
}
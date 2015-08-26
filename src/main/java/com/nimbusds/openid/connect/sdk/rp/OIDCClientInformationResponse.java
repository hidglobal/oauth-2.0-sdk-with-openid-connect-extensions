package com.nimbusds.openid.connect.sdk.rp;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.client.ClientInformationResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * OpenID Connect client information response.
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 * Cache-Control: no-store
 * Pragma: no-cache
 *
 * {
 *  "client_id"                       : "s6BhdRkqt3",
 *  "client_secret"                   :"ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk",
 *  "client_secret_expires_at"        : 1577858400,
 *  "registration_access_token"       : "this.is.an.access.token.value.ffx83",
 *  "registration_client_uri"         : "https://server.example.com/connect/register?client_id=s6BhdRkqt3",
 *  "token_endpoint_auth_method"      : "client_secret_basic",
 *  "application_type"                : "web",
 *  "redirect_uris"                   : ["https://client.example.org/callback","https://client.example.org/callback2"],
 *  "client_name"                     : "My Example",
 *  "client_name#ja-Jpan-JP"          : "クライアント名",
 *  "logo_uri"                        : "https://client.example.org/logo.png",
 *  "subject_type"                    : "pairwise",
 *  "sector_identifier_uri"           : "https://other.example.net/file_of_redirect_uris.json",
 *  "jwks_uri"                        : "https://client.example.org/my_public_keys.jwks",
 *  "userinfo_encrypted_response_alg" : "RSA1_5",
 *  "userinfo_encrypted_response_enc" : "A128CBC-HS256",
 *  "contacts"                        : ["ve7jtb@example.org", "mary@example.org"],
 *  "request_uris"                    : ["https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"]
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 3.2 and 4.3.
 *     <li>OAuth 2.0 Dynamic Client Registration Management Protocol (RFC
 *         7592), section 3.
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591), section
 *         3.2.1.
 * </ul>
 */
@Immutable
public class OIDCClientInformationResponse extends ClientInformationResponse {
	
	
	/**
	 * Creates a new OpenID Connect client information response.
	 *
	 * @param clientInfo The OpenID Connect client information. Must not be
	 *                   {@code null}.
	 */
	public OIDCClientInformationResponse(final OIDCClientInformation clientInfo) {

		super(clientInfo);
	}
	
	
	/**
	 * Gets the OpenID Connect client information.
	 *
	 * @return The OpenID Connect client information.
	 */
	public OIDCClientInformation getOIDCClientInformation() {

		return (OIDCClientInformation)getClientInformation();
	}
	
	
	/**
	 * Parses an OpenID Connect client information response from the 
	 * specified HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The OpenID Connect client information response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an
	 *                        OpenID Connect client information response.
	 */
	public static OIDCClientInformationResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		httpResponse.ensureStatusCode(HTTPResponse.SC_OK, HTTPResponse.SC_CREATED);
		OIDCClientInformation clientInfo = OIDCClientInformation.parse(httpResponse.getContentAsJSONObject());
		return new OIDCClientInformationResponse(clientInfo);
	}
}

package com.nimbusds.openid.connect.sdk;


import java.net.URL;

import java.util.Set;

import com.nimbusds.oauth2.sdk.ParseException;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;



/**
 * OpenID Connect client register (associate) request.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * POST /connect/register HTTP/1.1
 * Content-Type: application/x-www-form-urlencoded
 * Host: server.example.com
 * Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJ ...
	 * 
 * operation=client_register
 * &amp;application_type=web
 * &amp;redirect_uris=https://client.example.org/callback%20https://client.example.org/callback2
 * &amp;client_name=My%20Example%20
 * &amp;client_name%23ja-Jpan-JP=ワタシ用の例
 * &amp;logo_url=https://client.example.org/logo.png
 * &amp;subject_type=pairwise
 * &amp;sector_identifier_url=https://othercompany.com/file_of_redirect_uris.json
 * &amp;token_endpoint_auth_method=client_secret_basic
 * &amp;jwk_url=https://client.example.org/my_rsa_public_key.jwk
 * &amp;userinfo_encrypted_response_alg=RSA1_5
 * &amp;userinfo_encrypted_response_enc=A128CBC+HS256
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 2.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-25)
 */
public class ClientRegisterRequest extends ClientDetailsRequest {


	/**
	 * Creates a new OpenID Connect client register (associate) request.
	 *
	 * @param redirectURIs The client redirect URIs. The set must not be
	 *                     {@code null} and must include at least one URL.
	 */
	public ClientRegisterRequest(final Set<URL> redirectURIs) {

		super(ClientRegistrationOperation.CLIENT_REGISTER, redirectURIs);
	}


	/**
	 * Creates a new OpenID Connect client register (associate) request.
	 *
	 * @param redirectURI The client redirect URI. Must not be 
	 *                    {@code null}.
	 */
	public ClientRegisterRequest(final URL redirectURI) {

		super(ClientRegistrationOperation.CLIENT_REGISTER, redirectURI);
	}


	/**
	 * Parses an OpenID Connect client register (associate) request from 
	 * the specified HTTP POST request.
	 *
	 * <p>Example HTTP request (GET):
	 *
	 * <pre>
	 * POST /connect/register HTTP/1.1
	 * Content-Type: application/x-www-form-urlencoded
	 * Host: server.example.com
	 * Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJ ...
		 * 
	 * operation=client_register
	 * &amp;application_type=web
	 * &amp;redirect_uris=https://client.example.org/callback%20https://client.example.org/callback2
	 * &amp;client_name=My%20Example%20
	 * &amp;client_name%23ja-Jpan-JP=ワタシ用の例
	 * &amp;logo_url=https://client.example.org/logo.png
	 * &amp;subject_type=pairwise
	 * &amp;sector_identifier_url=https://othercompany.com/file_of_redirect_uris.json
	 * &amp;token_endpoint_auth_method=client_secret_basic
	 * &amp;jwk_url=https://client.example.org/my_rsa_public_key.jwk
	 * &amp;userinfo_encrypted_response_alg=RSA1_5
	 * &amp;userinfo_encrypted_response_enc=A128CBC+HS256
	 * </pre>
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The client register request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        client register request.
	 */
	public static ClientRegisterRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		ClientDetailsRequest detReq = ClientDetailsRequest.parse(httpRequest);

		if (detReq.getOperation() != ClientRegistrationOperation.CLIENT_REGISTER)
			throw new ParseException("Invalid \"operation\" parameter", 
					         OIDCError.INVALID_OPERATION);
	
		ClientRegisterRequest req = new ClientRegisterRequest(detReq.getRedirectURIs());

		req.applyOptionalParameters(detReq.toParameters(true));

		return req;
	}
}
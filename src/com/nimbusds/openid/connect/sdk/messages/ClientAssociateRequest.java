package com.nimbusds.openid.connect.sdk.messages;


import java.net.URL;

import java.util.Set;



/**
 * Client associate (new registration) request.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * POST /connect/register HTTP/1.1
 * Accept: application/x-www-form-urlencoded
 * Host: server.example.com
 * Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJ ... fQ.8Gj_-sj ... _X
 * 
 * type=client_associate
 * &application_type=web
 * &redirect_uris=https://client.example.org/callback
 *     %20https://client.example.org/callback2
 * &application_name=My%20Example%20
 * &application_name%23ja-Hani-JP=
 * &logo_url=https://client.example.org/logo.png
 * &user_id_type=pairwise
 * &sector_identifier_url=
 *     https://othercompany.com/file_of_redirect_uris_for_our_sites.js
 * &token_endpoint_auth_type=client_secret_basic
 * &jwk_url=https://client.example.org/my_rsa_public_key.jwk
 * &userinfo_encrypted_response_alg=RSA1_5
 * &userinfo_encrypted_response_enc=A128CBC+HS256
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 2.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-12-17)
 */
public class ClientAssociateRequest extends ClientRegistrationRequest {


	/**
	 * Creates a new client associate (new registration) request.
	 *
	 * @param redirectURIs The client redirect URIs. The set must not be
	 *                     {@code null} and must include at least one URL.
	 */
	public ClientAssociateRequest(final Set<URL> redirectURIs) {

		super(ClientRegistrationType.CLIENT_ASSOCIATE, redirectURIs);
	}


	/**
	 * Creates a new client associate (new registration) request.
	 *
	 * @param redirectURI The client redirect URI. Must not be 
	 *                    {@code null}.
	 */
	public ClientAssociateRequest(final URL redirectURI) {

		super(ClientRegistrationType.CLIENT_ASSOCIATE, redirectURI);
	}
}
package com.nimbusds.openid.connect.sdk;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ResponseType;


/**
 * OpenID Connect {@link #ID_TOKEN id_token} response type value constant.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, sections 2 and 3.1.2.1.
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices.
 *     <li>OAuth 2.0 (RFC 6749), sections 3.1.1 and 4.1.1.
 * </ul>
 */
@Immutable
public class OIDCResponseTypeValue {

	
	/**
	 * ID Token response type.
	 */
	public static final ResponseType.Value ID_TOKEN = new ResponseType.Value("id_token");


	/**
	 * None response type, should not be combined with other response type
	 * values.
	 */
	public static final ResponseType.Value NONE = new ResponseType.Value("none");


	/**
	 * Prevents public instantiation.
	 */
	private OIDCResponseTypeValue() { }
}

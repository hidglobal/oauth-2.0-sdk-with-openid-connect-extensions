package com.nimbusds.openid.connect.sdk;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ResponseType;


/**
 * OpenID Connect authorisation response types. Extend the standard 
 * {@link com.nimbusds.oauth2.sdk.ResponseType OAuth 2.0 response types}.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages, section 2.1.1.
 *     <li>OAuth 2.0 (RFC 6749), sections 3.1.1 and 4.1.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public class OIDCResponseType {

	
	/**
	 * ID Token.
	 */
	public static final ResponseType ID_TOKEN = new ResponseType("id_token");


	/**
	 * Prevents public instantiation.
	 */
	private OIDCResponseType() { }
}

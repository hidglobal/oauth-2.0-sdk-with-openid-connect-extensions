package com.nimbusds.oauth2.sdk;


/**
 * Enumeration of OAuth 2.0 roles.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 1.1.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-16)
 */
public enum Role {

	/**
	 * An entity capable of granting access to a protected resource. When 
	 * the resource owner is a person, it is referred to as an end-user.
	 */
	RESOURCE_OWNER,


	/**
	 * The server hosting the protected resources, capable of accepting
	 * and responding to protected resource requests using access tokens.
	 */
	RESOURCE_SERVER,


	/**
	 * An application making protected resource requests on behalf of the
	* resource owner and with its authorization.  The term "client" does
	* not imply any particular implementation characteristics (e.g.,
	* whether the application executes on a server, a desktop, or other
	* devices).
	*/
	CLIENT,


	/**
	 * The server issuing access tokens to the client after successfully
	 * authenticating the resource owner and obtaining authorization.
	 */
	AUTHORIZATION_SERVER
}
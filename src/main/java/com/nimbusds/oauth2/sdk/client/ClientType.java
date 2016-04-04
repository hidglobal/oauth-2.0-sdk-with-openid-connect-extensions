package com.nimbusds.oauth2.sdk.client;


/**
 * Enumeration of the OAuth 2.0 client types.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 2.1.
 * </ul>
 */
public enum ClientType {


	/**
	 * Confidential. Clients capable of maintaining the confidentiality of
	 * their credentials (e.g., client implemented on a secure server with
	 * restricted access to the client credentials), or capable of secure
	 * client authentication using other means.
	 */
	CONFIDENTIAL,


	/**
	 * Public. Clients incapable of maintaining the confidentiality of their
	 * credentials (e.g., clients executing on the device used by the
	 * resource owner, such as an installed native application or a web
	 * browser-based application), and incapable of secure client
	 * authentication via any other means.
	 */
	PUBLIC
}
package com.nimbusds.oauth2.sdk.http;


import javax.mail.internet.ContentType;


/**
 * Common content types used in the OAuth 2.0 protocol and implementing 
 * applications.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-14)
 */
public interface CommonContentTypes {


	/**
	 * Content type {@code application/json}.
	 */
	public static final ContentType APPLICATION_JSON = new ContentType("application", "json", null);
	
	
	/**
	 * Content type {@code application/jwt}.
	 */
	public static final ContentType APPLICATION_JWT = new ContentType("application", "jwt", null);
	
	
	/**
	 * Content type {@code application/x-www-form-urlencoded}.
	 */
	public static final ContentType APPLICATION_URLENCODED = new ContentType("application", "x-www-form-urlencoded", null);
}

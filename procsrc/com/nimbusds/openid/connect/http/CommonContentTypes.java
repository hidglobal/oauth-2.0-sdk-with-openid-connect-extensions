package com.nimbusds.openid.connect.http;


import javax.mail.internet.ContentType;


/**
 * Common content types used in OpenID Connect.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-04-18)
 */
public class CommonContentTypes {


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
	
	
	/**
	 * Prevents instantiation.
	 */
	private CommonContentTypes() {
	
		// Nothing to do
	}
}

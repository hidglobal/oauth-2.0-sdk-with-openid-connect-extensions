package com.nimbusds.oauth2.sdk.http;


import javax.mail.internet.ContentType;
import javax.mail.internet.ParameterList;


/**
 * Common content types used in the OAuth 2.0 protocol and implementing 
 * applications. The character set all of content types is set to UTF-8.
 *
 * @author Vladimir Dzhuvinov
 */
public final class CommonContentTypes {


	/**
	 * The default character set.
	 */
	public static final String DEFAULT_CHARSET = "UTF-8";


	/**
	 * The default content type parameter list.
	 */
	private static final ParameterList PARAM_LIST = new ParameterList();


	/**
	 * Content type {@code application/json}.
	 */
	public static final ContentType APPLICATION_JSON = new ContentType("application", "json", PARAM_LIST);
	
	
	/**
	 * Content type {@code application/jwt}.
	 */
	public static final ContentType APPLICATION_JWT = new ContentType("application", "jwt", PARAM_LIST);
	
	
	/**
	 * Content type {@code application/x-www-form-urlencoded}.
	 */
	public static final ContentType APPLICATION_URLENCODED = new ContentType("application", "x-www-form-urlencoded", PARAM_LIST);


	static {

		PARAM_LIST.set("charset", DEFAULT_CHARSET);
	}
}

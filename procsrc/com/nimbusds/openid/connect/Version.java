package com.nimbusds.openid.connect;


/**
 * Version information about this SDK and the matching OpenID Connect draft
 * implementation.
 *
 * @author Vladimir Dzhuvinov
 * @version 0.9 (2012-05-16)
 */
public class Version {

	
	/**
	 * The matching OpenID Connect specification version.
	 */
	public static final String OPENID_CONNECT_VERSION = "1.0";
	
	
	/**
	 * This SDK version.
	 */
	public static final String SDK_VERSION = "0.9";
	
	
	/**
	 * Prevents instantiation.
	 */
	private Version() {
	
		// Nothing to do
	}

}

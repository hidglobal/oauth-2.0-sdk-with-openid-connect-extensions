package com.nimbusds.openid.connect.sdk;


/**
 * Version information about this OpenID Connect SDK and the matching protocol
 * standard.
 *
 * @author Vladimir Dzhuvinov
 */
public class Version {

	
	/**
	 * The matching OpenID Connect specification version.
	 */
	public static final String OPENID_CONNECT_VERSION = "1.0";
	
	
	/**
	 * This SDK version.
	 */
	public static final String SDK_VERSION = "$version$";
	
	
	/**
	 * Prevents instantiation.
	 */
	private Version() {
	
		// Nothing to do
	}
}

package com.nimbusds.openid.connect.sdk;


/**
 * Version information about this SDK and the matching OpenID Connect 
 * specification.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-21)
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

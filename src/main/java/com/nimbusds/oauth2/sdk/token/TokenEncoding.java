package com.nimbusds.oauth2.sdk.token;


/**
 * Enumeration of the possible token encodings.
 */
public enum TokenEncoding {


	/**
	 * Opaque secure identifier.
	 */
	IDENTIFIER,


	/**
	 * Self-contained, the authorisation is encoded (e.g. as JWT).
	 */
	SELF_CONTAINED
}

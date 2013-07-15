package com.nimbusds.openid.connect.sdk;


import com.nimbusds.oauth2.sdk.ResponseType;


/**
 * OpenID Connect response type validator.
 * 
 * @author Vladimir Dzhuvinov
 */
class OIDCResponseTypeValidator {
	
	
	/**
	 * Checks if the specified response type is valid in OpenID Connect.
	 * 
	 * @param rt The response type. Must not be {@code null}.
	 * 
	 * @throws IllegalArgumentException If the response type wasn't a valid
	 *                                  OpenID Connect response type.
	 */
	public static void validate(final ResponseType rt) {
		
		if (rt.isEmpty())
			throw new IllegalArgumentException("The response type must contain at least one value");
		
		if (rt.contains(ResponseType.Value.TOKEN) && rt.size() == 1)
			throw new IllegalArgumentException("The OpenID Connect response type cannot have token as the only value");
		
		for (ResponseType.Value rtValue: rt) {

			if (! rtValue.equals(ResponseType.Value.CODE) &&
			    ! rtValue.equals(ResponseType.Value.TOKEN) &&
			    ! rtValue.equals(OIDCResponseTypeValue.ID_TOKEN) )
				throw new IllegalArgumentException("Unsupported OpenID Connect response type value: " + rtValue);
		}
	}
	
	
	/**
	 * Prevents public instantiation.
	 */
	private OIDCResponseTypeValidator() {
		
	}
}

package com.nimbusds.openid.connect.sdk;


import java.util.Map;

import com.nimbusds.oauth2.sdk.ParseException;


/**
 * Enumeration of the {@link ClientRegistrationRequest client registration} 
 * operations.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-25)
 */
public enum ClientRegistrationOperation {

	
	/**
	 * New registration.
	 */
	CLIENT_REGISTER,


	/**
	 * Rotate client secret.
	 */
	ROTATE_SECRET,
	
	
	/**
	 * Update for a registered client.
	 */
	CLIENT_UPDATE;
	
	
	/**
	 * Returns the string identifier of this client registration type.
	 *
	 * @return The string identifier.
	 */
	@Override
	public String toString() {
	
		return super.toString().toLowerCase();
	}


	/**
	 * Parses a client registration {@code operation} from the specified
	 * parameter map.
	 *
	 * @param params The parameter map. Must not be {@code null}.
	 *
	 * @throws ParseException If the operation parameter is missing or
	 *                        invalid.
	 */
	public static ClientRegistrationOperation parse(final Map<String,String> params)
		throws ParseException {

		String value = params.get("operation");

		if (value == null)
			throw new ParseException("Missing \"operation\" parameter", OIDCError.INVALID_OPERATION);

		for (ClientRegistrationOperation op: values()) {
			       
			if (op.toString().equalsIgnoreCase(value))
				return op;
		}

		throw new ParseException("Invalid \"operation\" parameter", OIDCError.INVALID_OPERATION);
	}
}

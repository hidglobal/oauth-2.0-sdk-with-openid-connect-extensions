package com.nimbusds.oauth2.sdk.id;


import net.jcip.annotations.Immutable;


/**
 * JSON Web Token (JWT) identifier. This class is immutable.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-15)
 */
@Immutable
public final class JWTID extends Identifier {


	/**
	 * Creates a new JWT identifier with the specified value.
	 *
	 * @param value The JWT identifier value. Must not be {@code null} or
	 *              empty string.
	 */
	public JWTID(final String value) {

		super(value);
	}


	/**
	 * Creates a new JWT identifier with a randomly generated value of the
	 * specified length. The value will be made up of mixed-case 
	 * alphanumeric ASCII characters.
	 *
	 * @param length The number of characters. Must be a positive integer.
	 */
	public JWTID(final int length) {
	
		super(length);
	}
	
	
	/**
	 * Creates a new JWT identifier with a randomly generated value. The
	 * value will be made up of 32 mixed-case alphanumeric ASCII 
	 * characters.
	 */
	public JWTID() {

		super();
	}


	@Override
	public boolean equals(final Object object) {
	
		return object != null && 
		       object instanceof JWTID && 
		       this.toString().equals(object.toString());
	}
}
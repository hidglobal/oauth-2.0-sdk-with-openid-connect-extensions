package com.nimbusds.openid.connect.sdk.claims;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * The end-user's gender: Values defined by the OpenID Connect specification 
 * are {@link #FEMALE} and {@link #MALE} ({@code gender}). Other values may be
 * used when neither of the defined values are applicable. This class is
 * immutable.
 *
 * @author Vladimir Dzhuvinov
 */
@Immutable
public class Gender extends Identifier {

	
	/**
	 * Female gender claim value.
	 */
	public static final Gender FEMALE = new Gender("female");
	
	
	/**
	 * Male gender claim value.
	 */
	public static final Gender MALE = new Gender("male");
	
	 
	/**
	 * Creates a new gender with the specified value.
	 *
	 * @param value The gender value. Must not be {@code null}.
	 */
	public Gender(final String value) {
	
		super(value);
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof Gender &&
		       this.toString().equals(object.toString());
	}
}
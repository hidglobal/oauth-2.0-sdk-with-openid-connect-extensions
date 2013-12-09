package com.nimbusds.oauth2.sdk.id;


import java.util.ArrayList;
import java.util.List;

import net.jcip.annotations.Immutable;


/**
 * Audience identifier. This class is immutable.
 */
@Immutable
public final class Audience extends Identifier {


	/**
	 * Creates a new audience identifier with the specified value.
	 *
	 * @param value The audience identifier value. Must not be {@code null}
	 *              or empty string.
	 */
	public Audience(final String value) {

		super(value);
	}


	/**
	 * Creates a new audience identifier with a randomly generated value of 
	 * the specified byte length, Base64URL-encoded.
	 *
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 */
	public Audience(final int byteLength) {
	
		super(byteLength);
	}
	
	
	/**
	 * Creates a new audience identifier with a randomly generated 256-bit 
	 * (32-byte) value, Base64URL-encoded.
	 */
	public Audience() {

		super();
	}


	/**
	 * Returns a list consisting of this audience only.
	 *
	 * @return A list consisting of this audience only.
	 */
	public List<Audience> toSingleAudienceList() {

		List<Audience> audienceList = new ArrayList<Audience>(1);
		audienceList.add(this);
		return audienceList;
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof Audience &&
		       this.toString().equals(object.toString());
	}
}
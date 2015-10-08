package com.nimbusds.oauth2.sdk.id;


import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import net.jcip.annotations.Immutable;


/**
 * Audience identifier.
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
	 * Creates a new audience identifier with the specified URI value.
	 *
	 * @param value The URI value. Must not be {@code null}.
	 */
	public Audience(final URI value) {

		super(value.toString());
	}


	/**
	 * Creates a new audience identifier with the specified value.
	 *
	 * @param value The value. Must not be {@code null}.
	 */
	public Audience(final Identifier value) {

		super(value.getValue());
	}


	/**
	 * Returns a list consisting of this audience only.
	 *
	 * @return A list consisting of this audience only.
	 */
	public List<Audience> toSingleAudienceList() {

		List<Audience> audienceList = new ArrayList<>(1);
		audienceList.add(this);
		return audienceList;
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof Audience &&
		       this.toString().equals(object.toString());
	}
}
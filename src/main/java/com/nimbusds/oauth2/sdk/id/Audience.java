package com.nimbusds.oauth2.sdk.id;


import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
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


	/**
	 * Returns a string list representation of the specified audience.
	 *
	 * @param audience The audience. May be {@code null}.
	 *
	 * @return The string list, {@code null} if the argument was
	 *         {@code null}.
	 */
	public static List<String> toStringList(final Audience audience) {

		if (audience == null) {
			return null;
		}
		return Collections.singletonList(audience.getValue());
	}


	/**
	 * Returns a string list representation of the specified audience list.
	 *
	 * @param audienceList The audience list. May be {@code null}.
	 *
	 * @return The string list, {@code null} if the argument was
	 *         {@code null}.
	 */
	public static List<String> toStringList(final List<Audience> audienceList) {

		if (audienceList == null) {
			return null;
		}

		List<String> list = new ArrayList<>(audienceList.size());
		for (Audience aud: audienceList) {
			list.add(aud.getValue());
		}
		return list;
	}


	/**
	 * Creates an audience list from the specified string list
	 * representation.
	 *
	 * @param strings The string list. May be {@code null}.
	 *
	 * @return The audience list, {@code null} if the argument was
	 *         {@code null}.
	 */
	public static List<Audience> create(final List<String> strings) {

		if (strings == null) {
			return null;
		}

		List<Audience> audienceList = new ArrayList<>(strings.size());

		for (String s: strings) {
			audienceList.add(new Audience(s));
		}
		return audienceList;
	}
}
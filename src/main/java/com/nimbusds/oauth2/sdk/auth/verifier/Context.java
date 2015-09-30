package com.nimbusds.oauth2.sdk.auth.verifier;


import net.jcip.annotations.ThreadSafe;


/**
 * Generic context for passing objects.
 */
@ThreadSafe
public class Context<T> {


	/**
	 * The context content.
	 */
	private T o;


	/**
	 * Sets the context content.
	 *
	 * @param o The context content.
	 */
	public void set(final T o) {

		this.o = o;
	}


	/**
	 * Gets the context content.
	 *
	 * @return The context content.
	 */
	public T get() {

		return o;
	}
}

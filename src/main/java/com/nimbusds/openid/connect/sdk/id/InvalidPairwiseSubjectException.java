package com.nimbusds.openid.connect.sdk.id;


/**
 * Invalid pairwise subject exception.
 */
public class InvalidPairwiseSubjectException extends Exception {
	

	/**
	 * Creates a new invalid pairwise subject exception.
	 *
	 * @param message The exception message.
	 */
	public InvalidPairwiseSubjectException(final String message) {
		super(message);
	}


	/**
	 * Creates a new invalid pairwise subject exception.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public InvalidPairwiseSubjectException(final String message, final Throwable cause) {
		super(message, cause);
	}
}

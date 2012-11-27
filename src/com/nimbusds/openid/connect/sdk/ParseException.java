package com.nimbusds.openid.connect.sdk;


import java.net.URL;

import com.nimbusds.openid.connect.sdk.messages.ErrorCode;
import com.nimbusds.openid.connect.sdk.messages.State;


/**
 * Parse exception.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-11-27)
 */
public class ParseException extends OpenIDConnectException {


	/**
	 * Creates a new parse exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 */
	public ParseException(final String message) {
	
		this(message, null, null);
	}
	
	
	/**
	 * Creates a new parse exception.
	 *
	 * @param message The exception message. May be {@code null}.
	 * @param cause   The exception cause, {@code null} if not specified.
	 */
	public ParseException(final String message, final Throwable cause) {
	
		this(message, null, cause);
	}


	/**
	 * Creates a new parse exception. Implies a HTTP status code
	 * {@link #HTTP_SC_BAD_REQUEST 400}.
	 *
	 * @param message   The exception message.
	 * @param errorCode Associated OpenID Connect error code.
	 */
	public ParseException(final String message, 
		              final ErrorCode errorCode) {
	
		this(message, errorCode, null);
	}


	/**
	 * Creates a new parse exception. Implies a HTTP status code
	 * {@link #HTTP_SC_BAD_REQUEST 400}.
	 *
	 * @param message   The exception message. May be {@code null}.
	 * @param errorCode The associated OpenID Connect / OAuth 2.0 error 
	 *                  code, {@code null} if not specified.
	 * @param cause     The exception cause, {@code null} if not specified.
	 */
	public ParseException(final String message, 
		              final ErrorCode errorCode,
		              final Throwable cause) {
	
		super(message, errorCode, cause);
	}


	/**
	 * Creates a new parse exception. Implies a HTTP status code
	 * {@link #HTTP_SC_FOUND 302}.
	 *
	 * @param message     The exception message. May be {@code null}.
	 * @param errorCode   The associated OpenID Connect / OAuth 2.0 
	 *                    error code, {@code null} if not specified.
	 * @param redirectURI The associated redirection URI, must not be 
	 *                    {@code null}.
	 * @param state       The optional associated state parameter, 
	 *                    {@code null} if not specified.
	 * @param cause       The exception cause, {@code null} if not
	 *                    specified.
	 */
	public ParseException(final String message, 
		              final ErrorCode errorCode,
		              final URL redirectURI,
		              final State state,
		              final Throwable cause) {

		super(message, errorCode, redirectURI, state, cause);
	}
}

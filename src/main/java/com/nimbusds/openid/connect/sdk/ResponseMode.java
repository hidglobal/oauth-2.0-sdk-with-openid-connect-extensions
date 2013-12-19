package com.nimbusds.openid.connect.sdk;


import net.jcip.annotations.Immutable;

import org.apache.commons.lang3.StringUtils;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * OAuth 2.0 response mode.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices, section 2.1.
 * </ul>
 */
@Immutable
public final class ResponseMode extends Identifier {


	/**
	 * Query response mode. In this mode, response parameters are encoded
	 * in the query string added to the {@code redirect_uri} when
	 * redirecting back to the client.
	 */
	public static final ResponseMode QUERY = new ResponseMode("query");


	/**
	 * Fragment response mode. In this mode, response parameters are
	 * encoded in the fragment added to the {@code redirect_uri} when
	 * redirecting back to the client.
	 */
	public static final ResponseMode FRAGMENT = new ResponseMode("fragment");


	/**
	 * HTML form post response mode. In this mode, response parameters are
	 * encoded as HTML form values that are auto-submitted in the
	 * user-agent, and thus are transmitted via the HTTP POST method to the
	 * client, with the result parameters being encoded in the response
	 * body using the {@code application/x-www-form-urlencoded} format.
	 * The action attribute of the form must be the client's Redirection
	 * URI. The method of the form attribute must be POST.
	 */
	public static final ResponseMode FORM_POST = new ResponseMode("form_post");


	/**
	 * Creates a new response mode with the specified value.
	 *
	 * @param value The response mode value. Must not be {@code null} or
	 *              empty string.
	 */
	public ResponseMode(final String value) {

		super(value);
	}


	@Override
	public boolean equals(final Object object) {

		return object instanceof ResponseMode &&
			this.toString().equals(object.toString());
	}


	/**
	 * Parses a response mode from the specified string.
	 *
	 * @param s The string to parse, {@code null} or empty if no response
	 *          mode is specified.
	 *
	 * @return The response mode, {@code null} if the parsed string was
	 *         {@code null} or empty.
	 */
	public static ResponseMode parse(final String s) {

		if (StringUtils.isBlank(s))
			return null;

		if (s.equals(ResponseMode.QUERY.getValue())) {
			return ResponseMode.QUERY;
		} else if (s.equals(ResponseMode.FRAGMENT.getValue())) {
			return ResponseMode.FRAGMENT;
		} else if (s.equals(ResponseMode.FORM_POST.getValue())) {
			return ResponseMode.FORM_POST;
		} else {
			return new ResponseMode(s);
		}
	}
}

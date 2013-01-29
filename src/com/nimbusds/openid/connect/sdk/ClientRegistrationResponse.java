package com.nimbusds.openid.connect.sdk;


import java.util.Date;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.BearerTokenError;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.SuccessResponse;

import com.nimbusds.oauth2.sdk.auth.Secret;

import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * The base abstract class for OpenID Connect client registration responses.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, sections 2.2 and
 *         2.3.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-29)
 */
public abstract class ClientRegistrationResponse implements Response {


	/**
	 * Returns the matching JSON object.
	 *
	 * @return The JSON object, {@code null} if not applicable.
	 */
	public abstract JSONObject toJSONObject();


	@Override
	public HTTPResponse toHTTPResponse() {

		HTTPResponse httpResponse = null;

		if (this instanceof SuccessResponse) {

			new HTTPResponse(HTTPResponse.SC_OK);

			httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
			httpResponse.setCacheControl("no-store");
			httpResponse.setContent(toJSONObject().toString());	
		}
		else if (this instanceof ErrorResponse) {

			OAuth2Error error = ((ErrorResponse)this).getOAuth2Error();

			if (error.getHTTPStatusCode() > 0)
				httpResponse = new HTTPResponse(error.getHTTPStatusCode());
			else
				httpResponse = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST);

			if (error instanceof BearerTokenError) {

				httpResponse.setWWWAuthenticate(((BearerTokenError)error).toWWWAuthenticateHeader());
			}
			else {
				JSONObject jsonObject = toJSONObject();

				if (jsonObject != null) {

					httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
					httpResponse.setCacheControl("no-store");
					httpResponse.setContent(jsonObject.toString());
				}
			}
		}

		return httpResponse;
	}


	/**
	 * Parses a client secret from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The client secret with optional expiration date, 
	 *         {@code null} if none specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	protected static Secret parseClientSecret(final JSONObject jsonObject)
		throws ParseException {

		if (! jsonObject.containsKey("client_secret"))
			return null;

		Date expDate = null;

		if (jsonObject.containsKey("expires_at"));
			expDate = new Date(JSONObjectUtils.getLong(jsonObject, "expires_at"));

		return new Secret(JSONObjectUtils.getString(jsonObject, "clientSecret"), expDate);
	}


	/**
	 * Parses an OpenID Connect client registration error from the 
	 * specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The OpenID Connect client registration error.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        OpenID Connect client registration error.
	 */
	protected static OAuth2Error parseError(final JSONObject jsonObject)
		throws ParseException {

		String errorCode = JSONObjectUtils.getString(jsonObject, "error_code");

		String errorDescription = null;

		if (jsonObject.containsKey("error_description"))
			errorDescription = JSONObjectUtils.getString(jsonObject, "error_description");

		return new OAuth2Error(errorCode, errorDescription, HTTPResponse.SC_BAD_REQUEST);
	}


	/**
	 * Parses an OpenID Connect client registration error from the 
	 * specified HTTP response.
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @return The OpenID Connect client registration error, {@code null}
	 *         if another error was found.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to
	 *                        an error.
	 */
	protected static OAuth2Error parseError(final HTTPResponse httpResponse)
		throws ParseException {

		httpResponse.ensureStatusCodeNotOK();

		// OAuth 2.0 Bearer token error?
		if (httpResponse.getWWWAuthenticate() != null)
			return BearerTokenError.parse(httpResponse.getWWWAuthenticate());


		// Client reg specific error?
		if (httpResponse.getStatusCode() == HTTPResponse.SC_BAD_REQUEST &&
		    httpResponse.getContentType() != null &&
		    httpResponse.getContentType().equals(CommonContentTypes.APPLICATION_JSON)) {

			JSONObject jsonObject = httpResponse.getContentAsJSONObject();

			return parseError(jsonObject);
		}

		// Other error
		return null;
	}
}
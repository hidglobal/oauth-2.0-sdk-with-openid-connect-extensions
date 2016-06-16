package com.nimbusds.oauth2.sdk;


import java.util.Date;
import java.util.List;

import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;


/**
 * Token introspection success response.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Token Introspection (RFC 7662).
 * </ul>
 */
@Immutable
public class TokenIntrospectionSuccessResponse extends TokenIntrospectionResponse implements SuccessResponse {


	/**
	 * Builder for constructing token introspection success responses.
	 */
	public static class Builder {


		/**
		 * Determines whether the token is active.
		 */
		private final boolean active;


		/**
		 * The optional token scope.
		 */
		private Scope scope;


		/**
		 * The optional client ID for the token.
		 */
		private ClientID clientID;


		/**
		 * The optional username for the token.
		 */
		private String username;


		/**
		 * The optional token type.
		 */
		private AccessTokenType tokenType;


		/**
		 * The optional token expiration date.
		 */
		private Date exp;


		/**
		 * The optional token issue date.
		 */
		private Date iat;


		/**
		 * The optional token not-before date.
		 */
		private Date nbf;


		/**
		 * The optional token subject.
		 */
		private Subject sub;


		/**
		 * The optional token audience.
		 */
		private List<Audience> audList;


		/**
		 * The optional token issuer.
		 */
		private Issuer iss;


		/**
		 * The optional token identifier.
		 */
		private JWTID jti;


		/**
		 * Optional custom parameters.
		 */
		private final JSONObject customParams = new JSONObject();


		/**
		 * Creates a new token introspection success response builder.
		 *
		 * @param active {@code true} if the token is active, else
		 *               {@code false}.
		 */
		public Builder(final boolean active) {

			this.active = active;
		}


		/**
		 * Sets the token scope.
		 *
		 * @param scope The token scope, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder scope(final Scope scope) {
			this.scope = scope;
			return this;
		}


		/**
		 * Sets the identifier for the OAuth 2.0 client that requested
		 * the token.
		 *
		 * @param clientID The client identifier, {@code null} if not
		 *                 specified.
		 *
		 * @return This builder.
		 */
		public Builder clientID(final ClientID clientID) {
			this.clientID = clientID;
			return this;
		}


		/**
		 * Sets the username of the resource owner who authorised the
		 * token.
		 *
		 * @param username The username, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder username(final String username) {
			this.username = username;
			return this;
		}


		/**
		 * Sets the token type.
		 *
		 * @param tokenType The token type, {@code null} if not
		 *                  specified.
		 *
		 * @return This builder.
		 */
		public Builder tokenType(final AccessTokenType tokenType) {
			this.tokenType = tokenType;
			return this;
		}


		/**
		 * Sets the token expiration time.
		 *
		 * @param exp The token expiration time, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder expirationTime(final Date exp) {
			this.exp = exp;
			return this;
		}


		/**
		 * Sets the token issue time.
		 *
		 * @param iat The token issue time, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder issueTime(final Date iat) {
			this.iat = iat;
			return this;
		}


		/**
		 * Sets the token not-before time.
		 *
		 * @param nbf The token not-before time, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder notBeforeTime(final Date nbf) {
			this.nbf = nbf;
			return this;
		}


		/**
		 * Sets the token subject.
		 *
		 * @param sub The token subject, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder subject(final Subject sub) {
			this.sub = sub;
			return this;
		}


		/**
		 * Sets the token audience.
		 *
		 * @param audList The token audience, {@code null} if not
		 *                specified.
		 *
		 * @return This builder.
		 */
		public Builder audience(final List<Audience> audList) {
			this.audList = audList;
			return this;
		}


		/**
		 * Sets the token issuer.
		 *
		 * @param iss The token issuer, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder issuer(final Issuer iss) {
			this.iss = iss;
			return this;
		}


		/**
		 * Sets the token identifier.
		 *
		 * @param jti The token identifier, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder jwtID(final JWTID jti) {
			this.jti = jti;
			return this;
		}


		/**
		 * Sets a custom parameter.
		 *
		 * @param name  The parameter name. Must not be {@code null}.
		 * @param value The parameter value. Should map to a JSON type.
		 *              If {@code null} not specified.
		 *
		 * @return This builder.
		 */
		public Builder parameter(final String name, final Object value) {
			if (value != null) {
				customParams.put(name, value);
			}
			return this;
		}


		/**
		 * Builds a new token introspection success response.
		 *
		 * @return The token introspection success response.
		 */
		public TokenIntrospectionSuccessResponse build() {

			JSONObject o = new JSONObject();
			o.put("active", active);
			if (scope != null) o.put("scope", scope.toString());
			if (clientID != null) o.put("client_id", clientID.getValue());
			if (username != null) o.put("username", username);
			if (tokenType != null) o.put("token_type", tokenType.getValue());
			if (exp != null) o.put("exp", DateUtils.toSecondsSinceEpoch(exp));
			if (iat != null) o.put("iat", DateUtils.toSecondsSinceEpoch(iat));
			if (nbf != null) o.put("nbf", DateUtils.toSecondsSinceEpoch(nbf));
			if (sub != null) o.put("sub", sub.getValue());
			if (audList != null) o.put("aud", Audience.toStringList(audList));
			if (iss != null) o.put("iss", iss.getValue());
			if (jti != null) o.put("jti", jti.getValue());
			o.putAll(customParams);
			return new TokenIntrospectionSuccessResponse(o);
		}
	}


	/**
	 * The parameters.
	 */
	private final JSONObject params;


	/**
	 * Creates a new token introspection success response.
	 *
	 * @param params The response parameters. Must contain at least the
	 *               required {@code active} parameter and not be
	 *               {@code null}.
	 */
	public TokenIntrospectionSuccessResponse(final JSONObject params) {

		if (! (params.get("active") instanceof Boolean)) {
			throw new IllegalArgumentException("Missing / invalid boolean active parameter");
		}

		this.params = params;
	}


	/**
	 * Returns the active status for the token. Corresponds to the
	 * {@code active} claim.
	 *
	 * @return {@code true} if the token is active, else {@code false}.
	 */
	public boolean isActive() {

		try {
			return JSONObjectUtils.getBoolean(params, "active");
		} catch (ParseException e) {
			return false; // always false on error
		}
	}


	/**
	 * Returns the scope of the token. Corresponds to the {@code scope}
	 * claim.
	 *
	 * @return The token scope, {@code null} if not specified.
	 */
	public Scope getScope() {

		try {
			return Scope.parse(JSONObjectUtils.getString(params, "scope"));
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Returns the identifier of the OAuth 2.0 client that requested the
	 * token. Corresponds to the {@code client_id} claim.
	 *
	 * @return The client identifier, {@code null} if not specified.
	 */
	public ClientID getClientID() {

		try {
			return new ClientID(JSONObjectUtils.getString(params, "client_id"));
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Returns the username of the resource owner who authorised the token.
	 * Corresponds to the {@code username} claim.
	 *
	 * @return The username, {@code null} if not specified.
	 */
	public String getUsername() {

		try {
			return JSONObjectUtils.getString(params, "username");
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Returns the access token type. Corresponds to the {@code token_type}
	 * claim.
	 *
	 * @return The token type, {@code null} if not specified.
	 */
	public AccessTokenType getTokenType() {

		try {
			return new AccessTokenType(JSONObjectUtils.getString(params, "token_type"));
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Returns the token expiration time. Corresponds to the {@code exp}
	 * claim.
	 *
	 * @return The token expiration time, {@code null} if not specified.
	 */
	public Date getExpirationTime() {

		try {
			return DateUtils.fromSecondsSinceEpoch(JSONObjectUtils.getLong(params, "exp"));
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Returns the token issue time. Corresponds to the {@code iat} claim.
	 *
	 * @return The token issue time, {@code null} if not specified.
	 */
	public Date getIssueTime() {

		try {
			return DateUtils.fromSecondsSinceEpoch(JSONObjectUtils.getLong(params, "iat"));
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Returns the token not-before time. Corresponds to the {@code nbf}
	 * claim.
	 *
	 * @return The token not-before time, {@code null} if not specified.
	 */
	public Date getNotBeforeTime() {

		try {
			return DateUtils.fromSecondsSinceEpoch(JSONObjectUtils.getLong(params, "nbf"));
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Returns the subject of the token, usually a machine-readable
	 * identifier of the resource owner who authorised the token.
	 * Corresponds to the {@code sub} claim.
	 *
	 * @return The token subject, {@code null} if not specified.
	 */
	public Subject getSubject() {

		try {
			return new Subject(JSONObjectUtils.getString(params, "sub"));
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Returns the intended audience for the token. Corresponds to the
	 * {@code aud} claim.
	 *
	 * @return The token audience, {@code null} if not specified.
	 */
	public List<Audience> getAudience() {
		// Try string array first, then string
		try {
			return Audience.create(JSONObjectUtils.getStringList(params, "aud"));
		} catch (ParseException e) {
			try {
				return new Audience(JSONObjectUtils.getString(params, "aud")).toSingleAudienceList();
			} catch (ParseException e2) {
				return null;
			}
		}
	}


	/**
	 * Returns the token issuer. Corresponds to the {@code iss} claim.
	 *
	 * @return The token issuer, {@code null} if not specified.
	 */
	public Issuer getIssuer() {

		try {
			return new Issuer(JSONObjectUtils.getString(params, "iss"));
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Returns the token identifier. Corresponds to the {@code jti}
	 * claim.
	 *
	 * @return The token identifier, {@code null} if not specified.
	 */
	public JWTID getJWTID() {

		try {
			return new JWTID(JSONObjectUtils.getString(params, "jti"));
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Returns a JSON object representation of this token introspection
	 * success response.
	 *
	 * <p>Example JSON object:
	 *
	 * <pre>
	 * {
	 *  "active"          : true,
	 *  "client_id"       : "l238j323ds-23ij4",
	 *  "username"        : "jdoe",
	 *  "scope"           : "read write dolphin",
	 *  "sub"             : "Z5O3upPC88QrAjx00dis",
	 *  "aud"             : "https://protected.example.net/resource",
	 *  "iss"             : "https://server.example.com/",
	 *  "exp"             : 1419356238,
	 *  "iat"             : 1419350238,
	 *  "extension_field" : "twenty-seven"
	 * }
	 * </pre>
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {

		return new JSONObject(params);
	}
	

	@Override
	public boolean indicatesSuccess() {

		return true;
	}


	@Override
	public HTTPResponse toHTTPResponse() {

		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		httpResponse.setContent(params.toJSONString());
		return httpResponse;
	}


	/**
	 * Parses a token introspection success response from the specified
	 * JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The token introspection success response.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        token introspection success response.
	 */
	public static TokenIntrospectionSuccessResponse parse(final JSONObject jsonObject)
		throws ParseException {

		try {
			return new TokenIntrospectionSuccessResponse(jsonObject);
		} catch (IllegalArgumentException e) {
			throw new ParseException(e.getMessage(), e);
		}
	}


	/**
	 * Parses an token introspection success response from the specified
	 * HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The token introspection success response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a
	 *                        token introspection success response.
	 */
	public static TokenIntrospectionSuccessResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
		JSONObject jsonObject = httpResponse.getContentAsJSONObject();
		return parse(jsonObject);
	}
}

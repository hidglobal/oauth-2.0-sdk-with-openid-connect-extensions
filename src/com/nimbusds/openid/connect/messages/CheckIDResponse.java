package com.nimbusds.openid.connect.messages;


import net.minidev.json.JSONObject;

import com.nimbusds.openid.connect.ParseException;

import com.nimbusds.openid.connect.claims.IDTokenClaims;

import com.nimbusds.openid.connect.http.HTTPResponse;
import com.nimbusds.openid.connect.http.CommonContentTypes;

import com.nimbusds.openid.connect.util.JSONObjectUtils;


/**
 * Check ID response. The Check ID Endpoint returns the JSON-serialised claims 
 * associated with the ID Token. The {@code Content-Type} of the HTTP response
 * is {@code application/json}.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 * 
 * {
 *  "iss": "http://server.example.com",
 *  "user_id": "248289761001",
 *  "aud": "s6BhdRkqt3",
 *  "nonce": "n-0S6_WzA2Mj",
 *  "exp": 1311281970,
 *  "iat": 1311280970
 * }
 * </pre>
 *
 * <p>See 
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-17)
 */
public class CheckIDResponse implements SuccessResponse {


	/**
	 * The ID Token claims to return with the response.
	 */
	private IDTokenClaims claims;
	
	
	/**
	 * Creates a new check ID response with the specified ID Token claims.
	 *
	 * @param claims The ID Token claims. Must not be {@code null}.
	 */
	public CheckIDResponse(final IDTokenClaims claims) {
	
		if (claims == null)
			throw new NullPointerException("The ID Token claims must not be null");
			
		this.claims = claims;
	}
	
	
	/**
	 * Gets the ID Token claims.
	 *
	 * @return The ID Token claims.
	 */
	public IDTokenClaims getIDTokenClaims() {
	
		return claims;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public HTTPResponse toHTTPResponse() {
	
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
	
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		httpResponse.setContent(claims.toJSONObject().toString());
		
		return httpResponse;
	}
	
	
	/**
	 * Parses a check ID response from the specified HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The check ID response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a 
	 *                        valid check ID response.
	 */
	public static CheckIDResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		JSONObject o = httpResponse.getContentAsJSONObject();
		
		IDTokenClaims claims = IDTokenClaims.parse(o);
		
		return new CheckIDResponse(claims);
	}
}

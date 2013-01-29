package com.nimbusds.openid.connect.sdk;


import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.Response;


/**
 * Client registration response.
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
public interface ClientRegistrationResponse extends Response {


	/**
	 * Returns the matching JSON object.
	 *
	 * @return The JSON object, {@code null} if not applicable.
	 */
	public JSONObject toJSONObject();
}
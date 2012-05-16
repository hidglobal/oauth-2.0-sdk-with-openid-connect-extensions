package com.nimbusds.openid.connect.messages;


import java.util.HashMap;
import java.util.Map;

import net.minidev.json.JSONObject;

import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.claims.Claim;

import com.nimbusds.openid.connect.http.HTTPResponse;


/**
 * UserInfo response.
 *
 * <p>Example JSON object representing a UserInfo response:
 *
 * <pre>
 * {
 *   "user_id"     : "248289761001",
 *   "name"        : "Jane Doe",
 *   "given_name"  : "Jane",
 *   "family_name" : "Doe",
 *   "email"       : "janedoe@example.com",
 *   "picture"     : "http://example.com/janedoe/me.jpg"
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-16)
 */
public class UserInfoResponse implements SuccessResponse {


	/**
	 * The UserInfo claims, keyed by full (including LangTag) name.
	 */
	private Map<String,Claim> claims = new HashMap<String,Claim>();
	
	
	
	public UserInfoResponse() {
	
	
	}
	
	
	

	public JSONObject toJSONObject() {
		return null;
	}
	
	
	/**
	 * @inheritDoc
	 */
	public HTTPResponse toHTTPResponse() {
	
		return null;
	}
	
	
	public static UserInfoResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		return null;
	}
}

package com.nimbusds.openid.connect.messages;


import com.nimbusds.openid.connect.ParseException;
import com.nimbusds.openid.connect.SerializeException;

import com.nimbusds.openid.connect.http.HTTPResponse;


/**
 * UserInfo response.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-02)
 */
public class UserInfoResponse implements SuccessResponse {


	/**
	 * @inheritDoc
	 */
	public HTTPResponse toHTTPResponse() {
	
		return null;
	}

}

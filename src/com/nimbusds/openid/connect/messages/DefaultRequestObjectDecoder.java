package com.nimbusds.openid.connect.messages;


import net.minidev.json.JSONObject;

import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.JOSEException;


/**
 * Simple decoder of JOSE-encoded OpenID Connect request objects. This class is
 * thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-17)
 */
public class DefaultRequestObjectDecoder implements RequestObjectDecoder {


	@Override
	public JSONObject decodeRequestObject(final JOSEObject requestObject)
		throws JOSEException {
		
		return null;
	}
}

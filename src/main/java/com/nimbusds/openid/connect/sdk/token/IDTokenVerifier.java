package com.nimbusds.openid.connect.sdk.token;


import com.nimbusds.jose.JWEObject;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;


/**
 * Created by vd on 15-11-27.
 */
public class IDTokenVerifier {


	

	public IDTokenClaimsSet verify(final SignedJWT idToken)
		throws Exception {



		return null;
	}


	public IDTokenClaimsSet verify(final JWEObject idToken) {

		return null;
	}
}

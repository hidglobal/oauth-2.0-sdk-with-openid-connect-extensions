package com.nimbusds.openid.connect.sdk.token;


import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.security.Key;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.oauth2.sdk.http.DefaultResourceRetriever;
import com.nimbusds.oauth2.sdk.http.Resource;
import com.nimbusds.oauth2.sdk.http.ResourceRetriever;


/**
 * Created by vd on 15-11-30.
 */
public class OPKeySelector implements JWSKeySelector {


	/**
	 * The default HTTP connect timeout for JWK set retrieval, in
	 * milliseconds. Set to 250 milliseconds.
	 */
	public static final int DEFAULT_HTTP_CONNECT_TIMEOUT = 250;


	/**
	 * The default HTTP read timeout for JWK set retrieval, in
	 * milliseconds. Set to 250 milliseconds.
	 */
	public static final int DEFAULT_HTTP_READ_TIMEOUT = 250;


	/**
	 * The default HTTP entity size limit for JWK set retrieval, in bytes.
	 * Set to 50 KBytes.
	 */
	public static final int DEFAULT_HTTP_SIZE_LIMIT = 50 * 1024;


	private final JWKSet opJWKSet;


	private final URL opJWKSetURL;


	private final AtomicReference<JWKSet> cachedOPJWKSet = new AtomicReference<>();


	/**
	 * The HTTP connect timeout for JWK set retrieval, in milliseconds.
	 */
	private int httpConnectTimeout = DEFAULT_HTTP_CONNECT_TIMEOUT;


	/**
	 * The HTTP read timeout for JWK set retrieval, in milliseconds.
	 */
	private int httpReadTimeout = DEFAULT_HTTP_READ_TIMEOUT;


	/**
	 * The HTTP entity size limit for JWK set retrieval, in bytes.
	 */
	private int httpSizeLimit = DEFAULT_HTTP_SIZE_LIMIT;


	public OPKeySelector(final JWKSet opJWKSet) {

		if (opJWKSet == null) {
			throw new IllegalArgumentException("The OpenID Provider JWK set must not be null");
		}

		this.opJWKSet = opJWKSet;
		opJWKSetURL = null;
	}


	public OPKeySelector(final URL opJWKSetURL) {

		if (opJWKSetURL == null) {
			throw new IllegalArgumentException("The OpenID Provider JWK set URI must not be null");
		}
		this.opJWKSetURL = opJWKSetURL;
		opJWKSet = null;

		Thread t = new Thread() {
			public void run() {
				JWKSet jwkSet = retrieveJWKSet(opJWKSetURL);
				if (jwkSet != null) {
					cachedOPJWKSet.set(jwkSet);
				}
			}


		};
		t.setName("op-jwk-set-retriever["+ opJWKSetURL +"]");
		t.start();
	}


	private JWKSet retrieveJWKSet(final URL jwkSetURL) {

		ResourceRetriever resourceRetriever = new DefaultResourceRetriever(DEFAULT_HTTP_CONNECT_TIMEOUT, DEFAULT_HTTP_READ_TIMEOUT, DEFAULT_HTTP_SIZE_LIMIT);
		Resource res;
		try {
			res = resourceRetriever.retrieveResource(opJWKSetURL);
		} catch (IOException e) {
			return null;
		}
		try {
			return JWKSet.parse(res.getContent());
		} catch (java.text.ParseException e) {
			return null;
		}
	}


	public JWKSet getOpJWKSet() {
		return opJWKSet;
	}


	public URL getOpJWKSetURL() {
		return opJWKSetURL;
	}


	protected JWKMatcher createJWKMatcher(final JWSHeader jwsHeader) {

		if (JWSAlgorithm.Family.RSA)
	}


	@Override
	public List<? extends Key> selectJWSKeys(final JWSHeader header, final SecurityContext context) {



		JWKMatcher matcher = new JWKMatcher.Builder()

				.build();

		return null;
	}
}

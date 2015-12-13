package com.nimbusds.oauth2.sdk.assertions.saml2;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import net.jcip.annotations.ThreadSafe;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;


/**
 * SAML 2.0 assertion validator. Expects assertions signed with RSA-SHA256
 * (mandatory to implement XML signature).
 */
@ThreadSafe
public class SAML2AssertionValidator {


	/**
	 * List of the expected audience values.
	 */
	private final List<com.nimbusds.oauth2.sdk.id.Audience> expectedAudience;


	/**
	 * Creates a new SAML 2.0 assertion validator.
	 *
	 * @param expectedAudience The expected audience / recipient value(s).
	 *                         Must not be empty or {@code null}.
	 *
	 * @throws ConfigurationException If bootstrapping of the OpenSAML
	 *                                library failed.
	 */
	public SAML2AssertionValidator(final List<com.nimbusds.oauth2.sdk.id.Audience> expectedAudience)
		throws ConfigurationException {
		if (expectedAudience.isEmpty()) {
			throw new IllegalArgumentException("The expected audience / recipient list must not be empty");
		}
		this.expectedAudience = expectedAudience;
		DefaultBootstrap.bootstrap();
	}


	/**
	 * Returns the expected audience / recipient values.
	 *
	 * @return The expected audience / recipient values.
	 */
	public List<com.nimbusds.oauth2.sdk.id.Audience> getExpectedAudience() {

		return expectedAudience;
	}


	/**
	 * Parses a SAML 2.0 assertion from the specified XML string.
	 *
	 * @param xml The XML string. Must not be {@code null}.
	 *
	 * @return The SAML 2.0 assertion.
	 *
	 * @throws ValidationException If parsing of the assertion failed.
	 */
	public static Assertion parse(final String xml)
		throws ValidationException {

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setNamespaceAware(true);

		XMLObject xmlObject;

		try {
			DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();

			Document document = docBuilder.parse(new InputSource(new ByteArrayInputStream(xml.getBytes("utf-8"))));
			Element element = document.getDocumentElement();

			UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
			xmlObject = unmarshaller.unmarshall(element);

		} catch (ParserConfigurationException | IOException | SAXException | UnmarshallingException e) {
			throw new ValidationException("Assertion parsing failed: " + e.getMessage(), e);
		}

		if (! (xmlObject instanceof Assertion)) {
			throw new ValidationException("Top-level element not an assertion");
		}

		return (Assertion)xmlObject;
	}


	/**
	 * Checks the specified XML signature.
	 *
	 * @param signature The XML signature. Must not be {@code null}.
	 * @param publicKey The public RSA key to validate the signature. Must
	 *                  not be {@code null}.
	 *
	 * @throws ValidationException If the signature is invalid.
	 */
	public static void validateSignature(final Signature signature, final RSAPublicKey publicKey)
		throws ValidationException {

		BasicCredential publicCredential = new BasicCredential();
		publicCredential.setPublicKey(publicKey);
		publicCredential.setUsageType(UsageType.SIGNING);
		SignatureValidator signatureValidator = new SignatureValidator(publicCredential);
		signatureValidator.validate(signature);
	}


	/**
	 * Validates the required statements of the specified SAML 2.0
	 * assertion. See http://tools.ietf.org/html/rfc7522#section-3
	 *
	 * @param assertion The SAML 2.0 assertion. Must not be {@code null}.
	 *
	 * @throws ValidationException If the assertion is invalid.
	 */
	private void validateStatements(final Assertion assertion)
		throws ValidationException {

		final SAML2AssertionDetails assertionDetails;
		try {
			assertionDetails = SAML2AssertionDetails.parse(assertion);
		} catch (ParseException e) {
			throw new ValidationException(e.getMessage(), e);
		}

		// match audiences
		if (! com.nimbusds.oauth2.sdk.id.Audience.matchesAny(expectedAudience, assertionDetails.getAudience())) {
			throw new ValidationException("Audience mismatch");
		}

		// Check expiration, with 60 seconds permitted skew
		final Date now = new Date();

		if (! DateUtils.isAfter(assertionDetails.getExpirationTime(), now, 60)) {
			throw new ValidationException("Expired assertion");
		}

		if (assertionDetails.getNotBeforeTime() != null &&
			! DateUtils.isBefore(assertionDetails.getNotBeforeTime(), now, 60)) {
			throw new ValidationException("Assertion ahead of use time");
		}
	}


	/**
	 * Validates the specified SAML 2.0 assertion.
	 *
	 * @param xml          The SAML 2.0 assertion XML. Must not be
	 *                     {@code null}.
	 * @param rsaPublicKey The public RSA key to validate the signature.
	 *                     Must not be {@code null}.
	 *
	 * @return The validated SAML 2.0 assertion.
	 *
	 * @throws ValidationException If the assertion is invalid.
	 */
	public Assertion validate(final String xml, final RSAPublicKey rsaPublicKey)
		throws ValidationException {

		// Parse string to XML, then to SAML 2.0 assertion object
		Assertion assertion = parse(xml);

		// Validate signature profile
		SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
		profileValidator.validate(assertion.getSignature());

		// Validate signature itself
		validateSignature(assertion.getSignature(), rsaPublicKey);

		// Validate audience, expiration and other required statements
		validateStatements(assertion);

		return assertion; // OK
	}
}

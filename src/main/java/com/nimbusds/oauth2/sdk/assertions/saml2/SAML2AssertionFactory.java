package com.nimbusds.oauth2.sdk.assertions.saml2;


import java.security.interfaces.RSAPrivateKey;

import com.nimbusds.oauth2.sdk.SerializeException;
import net.jcip.annotations.ThreadSafe;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.impl.AssertionMarshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;


/**
 * Static SAML 2.0 bearer assertion factory.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Assertion Framework for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7521).
 *     <li>Security Assertion Markup Language (SAML) 2.0 Profile for OAuth 2.0
 *         Client Authentication and Authorization Grants (RFC 7522).
 * </ul>
 */
@ThreadSafe
public class SAML2AssertionFactory {


	/**
	 * Creates a new SAML 2.0 assertion.
	 *
	 * @param details    The SAML 2.0 bearer assertion details. Must not
	 *                   be {@code null}.
	 * @param xmlDsigAlg The XML digital signature algorithm. Must not be
	 *                   {@code null}.
	 * @param credential The appropriate credentials to facilitate signing
	 *                   of the assertion.
	 *
	 * @return The SAML 2.0 bearer assertion.
	 *
	 * @throws SerializeException If serialisation or signing failed.
	 */
	public static Assertion create(final SAML2AssertionDetails details,
				       final String xmlDsigAlg,
				       final Credential credential) {

		Assertion a = details.toSAML2Assertion();

		// Create signature element
		Signature signature = (Signature) Configuration.getBuilderFactory()
			.getBuilder(Signature.DEFAULT_ELEMENT_NAME)
			.buildObject(Signature.DEFAULT_ELEMENT_NAME);

		signature.setSigningCredential(credential);
		signature.setSignatureAlgorithm(xmlDsigAlg);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

		a.setSignature(signature);

		MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();

		try {
			// Perform actual signing
			marshallerFactory.getMarshaller(a).marshall(a);
			Signer.signObject(signature);
		} catch (MarshallingException | SignatureException e) {
			throw new SerializeException(e.getMessage(), e);
		}

		return a;
	}


	/**
	 * Creates a new SAML 2.0 assertion as an XML element.
	 *
	 * @param details    The SAML 2.0 bearer assertion details. Must not
	 *                   be {@code null}.
	 * @param xmlDsigAlg The XML digital signature algorithm. Must not be
	 *                   {@code null}.
	 * @param credential The appropriate credentials to facilitate signing
	 *                   of the assertion.
	 *
	 * @return The SAML 2.0 bearer assertion as an XML element.
	 *
	 * @throws SerializeException If serialisation or signing failed.
	 */
	public static Element createAsElement(final SAML2AssertionDetails details,
					      final String xmlDsigAlg,
					      final Credential credential) {

		Assertion a = create(details, xmlDsigAlg, credential);
		AssertionMarshaller assertionMarshaller = new AssertionMarshaller();
		try {
			return assertionMarshaller.marshall(a);
		} catch (MarshallingException e) {
			throw new SerializeException(e.getMessage(), e);
		}
	}


	/**
	 * Creates a new SAML 2.0 assertion as an XML string.
	 *
	 * @param details    The SAML 2.0 bearer assertion details. Must not
	 *                   be {@code null}.
	 * @param xmlDsigAlg The XML digital signature algorithm. Must not be
	 *                   {@code null}.
	 * @param credential The appropriate credentials to facilitate signing
	 *                   of the assertion.
	 *
	 * @return The SAML 2.0 bearer assertion as an XML string. Note that
	 *         an XML declaration is not present in the output string.
	 *
	 * @throws SerializeException If serialisation or signing failed.
	 */
	public static String createAsString(final SAML2AssertionDetails details,
					    final String xmlDsigAlg,
					    final Credential credential) {

		Element a = createAsElement(details, xmlDsigAlg, credential);
		String xml = XMLHelper.nodeToString(a);
		// Strip XML doc declaration
		final String header = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
		return xml.substring(header.length());
	}


	/**
	 * Creates a new SAML 2.0 assertion as an XML string, signed with the
	 * RSA-SHA256 XML digital signature algorithm (mandatory to implement).
	 *
	 * @param details       The SAML 2.0 bearer assertion details. Must not
	 *                      be {@code null}.
	 * @param rsaPrivateKey The private RSA key to sign the assertion. Must
	 *                      not be {@code null}.
	 *
	 * @return The SAML 2.0 bearer assertion as an XML string. Note that
	 *         an XML declaration is not present in the output string.
	 *
	 * @throws SerializeException If serialisation or signing failed.
	 */
	public static String createAsString(final SAML2AssertionDetails details,
					    final RSAPrivateKey rsaPrivateKey) {

		BasicCredential credential = new BasicCredential();
		credential.setPrivateKey(rsaPrivateKey);
		credential.setUsageType(UsageType.SIGNING);
		return createAsString(details, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, credential);
	}
}

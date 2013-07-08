package com.nimbusds.openid.connect.sdk;


import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import java.util.Collection;
import junit.framework.TestCase;


/**
 * Tests the claims request class.
 *
 * @author Vladimir Dzhuvinov
 */
public class ClaimsRequestTest extends TestCase {
	
	
	private static boolean containsVoluntaryClaimsRequestEntry(final Collection<ClaimsRequest.Entry> entries, 
		                                                   final String claimName) {
		
		for (ClaimsRequest.Entry en: entries) {
			
			if (en.getClaimName().equals(claimName) &&
			    en.getClaimRequirement().equals(ClaimRequirement.VOLUNTARY) &&
			    en.getLangTag() == null &&
			    en.getValue() == null &&
			    en.getValues() == null)
				
				return true;
		}
		
		return false;
	}
	
	
	public void testForScope() {
		
		Scope scope = Scope.parse("openid email profile phone address");
		
		ClaimsRequest cr = ClaimsRequest.forScope(scope);
		
		System.out.println(cr.toJSONObject());
		
		assertTrue(cr.getIDTokenClaims().isEmpty());
		
		Collection<ClaimsRequest.Entry> userInfoClaims = cr.getUserInfoClaims();
		
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "email_verified"));
		
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "given_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "family_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "middle_name"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "nickname"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "preferred_username"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "profile"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "picture"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "website"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "gender"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "birthdate"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "zoneinfo"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "locale"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "updated_at"));
		
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "phone_number"));
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "phone_number_verified"));
		
		assertTrue(containsVoluntaryClaimsRequestEntry(userInfoClaims, "address"));
		
		assertEquals(19, userInfoClaims.size());
	}
}
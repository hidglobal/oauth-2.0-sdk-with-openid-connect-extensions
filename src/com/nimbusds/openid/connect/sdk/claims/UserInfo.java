package com.nimbusds.openid.connect.sdk.claims;



/**
 * UserInfo claims. Implements all reserved claims returned at a UserInfo 
 * endpoint.
 *
 * <p>Example {@link com.nimbusds.openid.connect.sdk.claims.sets.UserInfoClaims
 * UserInfo claims set}:
 *
 * <pre>
 * {
 *   "sub"                : "248289761001",
 *   "name"               : "Jane Doe",
 *   "given_name"         : "Jane",
 *   "family_name"        : "Doe",
 *   "preferred_username" : "j.doe",
 *   "email"              : "janedoe@example.com",
 *   "picture"            : "http://example.com/janedoe/me.jpg"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.3.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-08)
 */
public class UserInfo {


	/**
	 * End-user's full name in displayable form including all name parts, 
	 * ordered according to end-user's locale and preferences 
	 * ({@code name}).
	 */
	public static class Name extends StringClaimWithLangTag {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "name".
		 */
		@Override
		public String getBaseClaimName() {
		
			return "name";
		}
	}
	
	
	/**
	 * Given name or first name of the end-user ({@code given_name}).
	 */
	public static class GivenName extends StringClaimWithLangTag {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "given_name".
		 */
		@Override
		public String getBaseClaimName() {
		
			return "given_name";
		}
	}
	
	
	/**
	 * Surname or last name of the end-user ({@code family_name}).
	 */
	public static class FamilyName extends StringClaimWithLangTag {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "family_name".
		 */
		@Override
		public String getBaseClaimName() {
		
			return "family_name";
		}
	}
	
	
	/**
	 * Middle name of the end-user ({@code middle_name}).
	 */
	public static class MiddleName extends StringClaimWithLangTag {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "middle_name".
		 */
		@Override
		public String getBaseClaimName() {
		
			return "middle_name";
		}
	}
	
	
	/**
	 * Casual name of the end-user that may or may not be the same as the
	 * given name ({@code nickname}). For instance, a nickname value of 
	 * {@code Mike} might be returned alongside a given name value of 
	 * {@code Michael}.
	 */
	public static class Nickname extends StringClaimWithLangTag {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "nickname".
		 */
		@Override
		public String getBaseClaimName() {
		
			return "nickname";
		}
	}
	
	
	/**
	 * Shorthand name that the end-user wished to be referred to at the 
	 * relying party, such as {@code janedoe} or {@code j.doe} 
	 * ({@code preferred_username}). The value may be any valid JSON string 
	 * including special characters such as {@code @}, {@code /} or 
	 * whitespace. The value must not be relied upon to be unique by the 
	 * relying party.
	 */
	public static class PreferredUsername extends StringClaim {
	
		
		/**
		 * @inheritDoc
		 *
		 * @return "preferred_username".
		 */
		@Override
		public String getClaimName() {
		
			return "preferred_username";
		}
	}
	
	
	/**
	 * URL of end-user's profile page ({@code profile}).
	 */
	public static class Profile extends URLClaim {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "profile".
		 */
		@Override
		public String getClaimName() {

			return "profile";
		}
	}
	
	
	/**
	 * URL of the end-user's profile picture ({@code picture}).
	 */
	public static class Picture extends URLClaim {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "picture".
		 */
		@Override
		public String getClaimName() {

			return "picture";
		}
	}
	
	
	/**
	 * URL of end-user's web page or blog ({@code website}).
	 */
	public static class Website extends URLClaim {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "website".
		 */
		@Override
		public String getClaimName() {

			return "website";
		}
	}
	
	
	/**
	 * The end-user's preferred e-mail address ({@code email}). The value 
	 * must not be relied upon to be unique by the relying party.
	 */
	public static class Email extends EmailClaim {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "email".
		 */
		@Override
		public String getClaimName() {

			return "email";
		}
	}
	
	
	/**
	 * {@code true} if the end-user's e-mail address has been verified; 
	 * otherwise {@code false} ({@code email_verified}).
	 */
	public static class EmailVerified extends BooleanClaim {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "email_verified".
		 */
		@Override
		public String getClaimName() {

			return "email_verified";
		}
	}
	
	
	/**
	 * The end-user's gender: Values defined by the specification are 
	 * {@link #FEMALE} and {@link #MALE} ({@code gender}). Other values may 
	 * be used when neither of the defined values are applicable.
	 */
	public static class Gender extends StringClaim {
	
		
		/**
		 * Female gender claim value.
		 */
		public static final String FEMALE = "female";
		
		
		/**
		 * Male gender claim value.
		 */
		public static final String MALE = "male";
		
		 
		/**
		 * @inheritDoc
		 *
		 * @return "gender".
		 */
		@Override
		public String getClaimName() {

			return "gender";
		}
	}
	
	
	/**
	 * The end-user's birthday, represented as a date string in MM/DD/YYYY 
	 * format ({@code birthday}). The year may be 0000, indicating that it 
	 * is omitted.
	 */
	public static class Birthday extends StringClaim {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "birthday".
		 */
		@Override
		public String getClaimName() {

			return "birthday";
		}
	}
	
	
	/**
	 * String from zoneinfo time zone database ({@code zoneinfo}). For 
	 * example, {@code Europe/Paris} or {@code America/Los_Angeles}.
	 */
	public static class Zoneinfo extends StringClaim {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "zoneinfo".
		 */
		public String getClaimName() {

			return "zoneinfo";
		}
	}
	
	
	/**
	 * The end-user's locale, represented as a language tag (RFC 5646) 
	 * ({@code locale}).
	 */
	public static class Locale extends LangTagClaim {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "locale".
		 */
		@Override
		public String getClaimName() {

			return "locale";
		}
	}
	
	
	/**
	 * The end-user's preferred telephone number ({@code phone_number}). 
	 * E.164 is recommended as the format of this claim. For example, 
	 * {@code +1 (425) 555-1212} or {@code +56 (2) 687 2400}.
	 */
	public static class PhoneNumber extends StringClaim {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "phone_number".
		 */
		@Override
		public String getClaimName() {

			return "phone_number";
		}
	}
	
	
	/**
	 * The end-user's preferred address ({@code address}). The serialised 
	 * address claim is a JSON object containing some or all of the members 
	 * defined below.
	 */
	public static class Address {
	
	
		/**
		 * The full mailing address, formatted for display or use with a 
		 * mailing label ({@code formatted}). This field may contain 
		 * newlines. This is the primary field for address claims, for 
		 * the purposes of sorting and filtering. 
		 */
		public static class Formatted extends StringClaimWithLangTag {
		
		
			/**
			 * @inheritDoc
			 *
			 * @return "formatted".
			 */
			@Override
			public String getBaseClaimName() {

				return "formatted";
			}
		}
		
		
		/**
		 * The full street address component, which may include house 
		 * number, street name, PO BOX, and multi-line extended street 
		 * address information ({@code street_address}). This field may 
		 * contain newlines. 
		 */
		public static class StreetAddress extends StringClaimWithLangTag {
		
		
			/**
			 * @inheritDoc
			 *
			 * @return "street_address".
			 */
			@Override
			public String getBaseClaimName() {

				return "street_address";
			}
		}
		
		
		/**
		 * The city or locality component ({@code locality}). 
		 */
		public static class Locality extends StringClaimWithLangTag {
		
		
			/**
			 * @inheritDoc
			 *
			 * @return "locality".
			 */
			@Override
			public String getBaseClaimName() {

				return "locality";
			}
		}
		
		
		/**
		 * The state, province, prefecture or region component
		 * ({@code region}). 
		 */
		public static class Region extends StringClaimWithLangTag {
		
		
			/**
			 * @inheritDoc
			 *
			 * @return "region".
			 */
			@Override
			public String getBaseClaimName() {

				return "region";
			}
		}
		
		
		/**
		 * The zip code or postal code component ({@code postal_code}).
		 */
		public static class PostalCode extends StringClaimWithLangTag {
		
		
			/**
			 * @inheritDoc
			 *
			 * @return "postal_code".
			 */
			@Override
			public String getBaseClaimName() {

				return "postal_code";
			}
		}
		
		
		/**
		 * The country name component ({@code country}).
		 */
		public static class Country extends StringClaimWithLangTag {
		
		
			/**
			 * @inheritDoc
			 *
			 * @return "country".
			 */
			@Override
			public String getBaseClaimName() {

				return "country";
			}
		}
	}
	
	
	/**
	 * Time the end-user's information was last updated, represented as a 
	 * RFC 3339 datetime ({@code updated_time}). For example, 
	 * {@code 2011-01-03T23:58:42+0000}.
	 */
	public static class UpdatedTime extends StringClaim {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "updated_time".
		 */
		@Override
		public String getClaimName() {

			return "updated_time";
		}
	}
}

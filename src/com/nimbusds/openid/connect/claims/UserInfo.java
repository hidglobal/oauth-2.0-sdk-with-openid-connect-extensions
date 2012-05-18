package com.nimbusds.openid.connect.claims;



/**
 * UserInfo claims.
 *
 * <p>Example UserInfo claims set:
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
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Messages 1.0, section 2.4.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-05-16)
 */
public class UserInfo {


	/**
	 * End-user's full name in displayable form including all name parts, 
	 * ordered according to end-user's locale and preferences.
	 */
	public static class Name extends StringClaimWithLangTag {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "name".
		 */
		public String getBaseClaimName() {
		
			return "name";
		}
		
	
		/**
		 * @inheritDoc
		 *
		 * @return "name" or "name#lang-tag".
		 */
		public String getClaimName() {

			if (langTag == null)
				return "name";
			else
				return "name" + langTag;
		}
	}
	
	
	/**
	 * Given name or first name of the end-user.
	 */
	public static class GivenName extends StringClaimWithLangTag {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "given_name".
		 */
		public String getBaseClaimName() {
		
			return "given_name";
		}
		
		
		/**
		 * @inheritDoc
		 *
		 * @return "given_name" or "given_name#lang-tag".
		 */
		public String getClaimName() {

			if (langTag == null)
				return "given_name";
			else
				return "given_name" + langTag.toString();
		}
	}
	
	
	/**
	 * Surname or last name of the end-user.
	 */
	public static class FamilyName extends StringClaimWithLangTag {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "family_name".
		 */
		public String getBaseClaimName() {
		
			return "family_name";
		}
		
		
		/**
		 * @inheritDoc
		 *
		 * @return "family_name" or "family_name#lang-tag".
		 */
		public String getClaimName() {

			if (langTag == null)
				return "family_name";
			else
				return "family_name" + langTag.toString();
		}
	}
	
	
	/**
	 * Middle name of the end-user.
	 */
	public static class MiddleName extends StringClaimWithLangTag {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "middle_name".
		 */
		public String getBaseClaimName() {
		
			return "middle_name";
		}
		
		
		/**
		 * @inheritDoc
		 *
		 * @return "middle_name" or "middle_name#lang-tag".
		 */
		public String getClaimName() {

			if (langTag == null)
				return "middle_name";
			else
				return "middle_name" + langTag.toString();
		}
	}
	
	
	/**
	 * Casual name of the end-user that may or may not be the same as the
	 * given name. For instance, a nickname value of Mike might be 
	 * returned alongside a given name value of Michael.
	 */
	public static class Nickname extends StringClaimWithLangTag {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "nickname".
		 */
		public String getBaseClaimName() {
		
			return "nickname";
		}
		
		
		/**
		 * @inheritDoc
		 *
		 * @return "nickname" or "nickname#lang-tag".
		 */
		public String getClaimName() {

			if (langTag == null)
				return "nickname";
			else
				return "nickname" + langTag.toString();
		}
	}
	
	
	/**
	 * URL of end-user's profile page.
	 */
	public static class Profile extends URLClaim {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "profile".
		 */
		public String getClaimName() {

			return "profile";
		}
	}
	
	
	/**
	 * URL of the end-user's profile picture.
	 */
	public static class Picture extends URLClaim {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "picture".
		 */
		public String getClaimName() {

			return "picture";
		}
	}
	
	
	/**
	 * URL of end-user's web page or blog.
	 */
	public static class Website extends URLClaim {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "website".
		 */
		public String getClaimName() {

			return "website";
		}
	}
	
	
	/**
	 * The end-user's preferred e-mail address.
	 */
	public static class Email extends EmailClaim {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "email".
		 */
		public String getClaimName() {

			return "email";
		}
	}
	
	
	/**
	 * {@code true} if the end-user's e-mail address has been verified; 
	 * otherwise {@code false}.
	 */
	public static class Verified extends BooleanClaim {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "verified".
		 */
		public String getClaimName() {

			return "verified";
		}
	}
	
	
	/**
	 * The end-user's gender: Values defined by this specification are 
	 * {@link #FEMALE} and {@link #MALE}. Other values may be used when 
	 * neither of the defined values are applicable.
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
		public String getClaimName() {

			return "gender";
		}
	}
	
	
	/**
	 * The end-user's birthday, represented as a date string in MM/DD/YYYY 
	 * format. The year may be 0000, indicating that it is omitted.
	 */
	public static class Birthday extends StringClaim {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "birthday".
		 */
		public String getClaimName() {

			return "birthday";
		}
	}
	
	
	/**
	 * String from zoneinfo time zone database. For example, 
	 * {@code Europe/Paris} or {@code America/Los_Angeles}.
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
	 * The end-user locale.
	 */
	public static class Locale extends LangTagClaim {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "locale".
		 */
		public String getClaimName() {

			return "locale";
		}
	}
	
	
	/**
	 * The end-user's preferred telephone number. E.164 is recommended as 
	 * the format of this claim. For example, {@code +1 (425) 555-1212} or 
	 * {@code +56 (2) 687 2400}.
	 */
	public static class PhoneNumber extends StringClaim {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "phone_number".
		 */
		public String getClaimName() {

			return "phone_number";
		}
	}
	
	
	/**
	 * The end-user's preferred address. 
	 */
	public static class Address {
	
	
		/**
		 * The full mailing address, formatted for display or use with a 
		 * mailing label. This field may contain newlines. This is the 
		 * primary sub-field for this field, for the purposes of sorting 
		 * and filtering. 
		 */
		public static class Formatted extends StringClaimWithLangTag {
		
		
			/**
			 * @inheritDoc
			 *
			 * @return "formatted".
			 */
			public String getBaseClaimName() {

				return "formatted";
			}
			
			
			/**
			 * @inheritDoc
			 *
			 * @return "formatted" or "formatted#lang-tag".
			 */
			public String getClaimName() {

				if (langTag == null)
					return "formatted";
				else
					return "formatted" + langTag.toString();
			}
		}
		
		
		/**
		 * The full street address component, which may include house 
		 * number, street name, PO BOX, and multi-line extended street 
		 * address information. This field may contain newlines. 
		 */
		public static class StreetAddress extends StringClaimWithLangTag {
		
		
			/**
			 * @inheritDoc
			 *
			 * @return "street_address".
			 */
			public String getBaseClaimName() {

				return "street_address";
			}
			
			
			/**
			 * @inheritDoc
			 *
			 * @return "street_address" or "street_address#lang-tag".
			 */
			public String getClaimName() {

				if (langTag == null)
					return "street_address";
				else
					return "street_address" + langTag.toString();
			}
		}
		
		
		/**
		 * The city or locality component. 
		 */
		public static class Locality extends StringClaimWithLangTag {
		
		
			/**
			 * @inheritDoc
			 *
			 * @return "locality".
			 */
			public String getBaseClaimName() {

				return "locality";
			}
			
			
			/**
			 * @inheritDoc
			 *
			 * @return "locality" or "locality#lang-tag".
			 */
			public String getClaimName() {

				if (langTag == null)
					return "locality";
				else
					return "locality" + langTag.toString();
			}
		}
		
		
		/**
		 * The state, province, prefecture or region component. 
		 */
		public static class Region extends StringClaimWithLangTag {
		
		
			/**
			 * @inheritDoc
			 *
			 * @return "region".
			 */
			public String getBaseClaimName() {

				return "region";
			}
			
			
			/**
			 * @inheritDoc
			 *
			 * @return "region" or "region#lang-tag".
			 */
			public String getClaimName() {

				if (langTag == null)
					return "region";
				else
					return "region" + langTag.toString();
			}
		}
		
		
		/**
		 * The zip code or postal code component.
		 */
		public static class PostalCode extends StringClaimWithLangTag {
		
		
			/**
			 * @inheritDoc
			 *
			 * @return "postal_code".
			 */
			public String getBaseClaimName() {

				return "postal_code";
			}
			
			
			/**
			 * @inheritDoc
			 *
			 * @return "postal_code" or "postal_code#lang-tag".
			 */
			public String getClaimName() {

				if (langTag == null)
					return "postal_code";
				else
					return "postal_code" + langTag.toString();
			}
		}
		
		
		/**
		 * The country name component.
		 */
		public static class Country extends StringClaimWithLangTag {
		
		
			/**
			 * @inheritDoc
			 *
			 * @return "country".
			 */
			public String getBaseClaimName() {

				return "country";
			}
			
			
			/**
			 * @inheritDoc
			 *
			 * @return "country" or "country#lang-tag".
			 */
			public String getClaimName() {

				if (langTag == null)
					return "country";
				else
					return "country" + langTag.toString();
			}
		}
	}
	
	
	/**
	 * Time the end-user's information was last updated, represented as a 
	 * RFC 3339 datetime. For example, {@code 2011-01-03T23:58:42+0000}.
	 */
	public static class UpdatedTime extends StringClaim {
	
	
		/**
		 * @inheritDoc
		 *
		 * @return "updated_time".
		 */
		public String getClaimName() {

			return "updated_time";
		}
	}
}

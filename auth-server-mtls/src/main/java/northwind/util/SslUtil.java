package northwind.util;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;


public class SslUtil {

	public static String computeThumbprint(X509Certificate x509Certificate) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] digest = md.digest(x509Certificate.getEncoded());
			return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
		} catch (Exception ex) {
			return null;
		}
	}
	
	public static String computeThumbprint(PublicKey publicKey) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] digest = md.digest(publicKey.getEncoded());
			return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
		} catch (Exception ex) {
			return null;
		}
	}
}

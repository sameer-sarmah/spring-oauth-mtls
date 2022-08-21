package northwind.authentication;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;


public final class X509ClientCertificateClaimValidator implements OAuth2TokenValidator<Jwt> {
	private static final OAuth2Error INVALID_CLIENT_ERROR = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT);

	@Override
	public OAuth2TokenValidatorResult validate(Jwt jwt) {
		X509Certificate x509Certificate = extractClientCertificate(RequestContextHolder.getRequestAttributes());
		if (x509Certificate == null) {
			return OAuth2TokenValidatorResult.failure(INVALID_CLIENT_ERROR);
		}

		String sha256Thumbprint = computeThumbprint(x509Certificate);
		if (sha256Thumbprint == null ||
				!sha256Thumbprint.equals(jwt.getClaim("x5tc#S256"))) {
			return OAuth2TokenValidatorResult.failure(INVALID_CLIENT_ERROR);
		}

		return OAuth2TokenValidatorResult.success();
	}

	private static X509Certificate extractClientCertificate(RequestAttributes requestAttributes) {
		X509Certificate[] certs = (X509Certificate[]) requestAttributes.getAttribute(
				"javax.servlet.request.X509Certificate", RequestAttributes.SCOPE_REQUEST);
		if (certs != null && certs.length > 0) {
			return certs[0];
		}
		return null;
	}

	private static String computeThumbprint(X509Certificate x509Certificate) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] digest = md.digest(x509Certificate.getEncoded());
			return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
		} catch (Exception ex) {
			return null;
		}
	}

}
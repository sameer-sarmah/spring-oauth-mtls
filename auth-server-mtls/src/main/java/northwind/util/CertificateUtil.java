package northwind.util;

import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import jakarta.servlet.ServletRequest;
import org.apache.commons.lang3.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.context.request.RequestAttributes;

public class CertificateUtil {
	private static final Logger LOGGER = LoggerFactory.getLogger(CertificateUtil.class);
	private static final String X509_CERTIFICATE_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";
	private static final String LEGACY_X509_CERTIFICATE_ATTRIBUTE = "javax.servlet.request.X509Certificate";
  
	public static void analyse(X509Certificate[] certificates) {
		Arrays.stream(certificates)
				.forEach(certificate -> analyse(certificate));
	}
	
	public static void analyse(X509Certificate certificate) {	
		Principal principal = certificate.getIssuerDN();
		boolean hasCertificateExpired = false;
		try {
			certificate.checkValidity();
		}catch(CertificateException e) {
			hasCertificateExpired = true;
		}
		String sha256Thumbprint = SslUtil.computeThumbprint(certificate);
		StringBuilder builder = new StringBuilder();
		builder.append("Principal=").append(principal.getName()).append(",")
				.append("hasCertificateExpired=").append(hasCertificateExpired).append(",")
				.append("algorithm=").append(certificate.getSigAlgName())
				.append("sha256Thumbprint=").append(sha256Thumbprint);
		LOGGER.info(builder.toString());
	}

	public static List<X509Certificate> extractCertificates(ServletRequest request){
		X509Certificate[] certificates = null;
		Object certAttribute = request.getAttribute(X509_CERTIFICATE_ATTRIBUTE);
		if (Objects.isNull(certAttribute)) {
			certAttribute = request.getAttribute(LEGACY_X509_CERTIFICATE_ATTRIBUTE);
		}
		if (certAttribute instanceof X509Certificate[]) {
			certificates = (X509Certificate[]) certAttribute;
		}
		return convertArrayToList(certificates);
	}

	public static List<X509Certificate> extractCertificates(RequestAttributes requestAttributes){
		X509Certificate[] certificates = null;
		Object certAttribute = requestAttributes.getAttribute(X509_CERTIFICATE_ATTRIBUTE,RequestAttributes.SCOPE_REQUEST);
		if (Objects.isNull(certAttribute)) {
			certAttribute = requestAttributes.getAttribute(LEGACY_X509_CERTIFICATE_ATTRIBUTE,RequestAttributes.SCOPE_REQUEST);
		}
		if (certAttribute instanceof X509Certificate[]) {
			certificates = (X509Certificate[]) certAttribute;
		}
		return convertArrayToList(certificates);
	}

	private static List<X509Certificate> convertArrayToList(X509Certificate[] certificates) {
		if(ArrayUtils.isNotEmpty(certificates)){
			return Arrays.asList(certificates);
		} else{
			return List.of();
		}
	}
}

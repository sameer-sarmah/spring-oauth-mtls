package northwind.util;

import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CertificateAnalyser {
	private static final Logger LOGGER = LoggerFactory.getLogger(CertificateAnalyser.class);
  
	public static void analyse(X509Certificate[] certificates) {	
		Stream<X509Certificate> certificatesStream = Arrays.stream(certificates);
		certificatesStream.forEach(certificate -> analyse(certificate));
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
}

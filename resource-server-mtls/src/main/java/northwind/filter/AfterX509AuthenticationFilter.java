package northwind.filter;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.web.filter.GenericFilterBean;

import northwind.util.CertificateUtil;

public class AfterX509AuthenticationFilter extends GenericFilterBean{

	private static final String X509_CERTIFICATE_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";
	private static final String LEGACY_X509_CERTIFICATE_ATTRIBUTE = "javax.servlet.request.X509Certificate";

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		List<X509Certificate> x509Certificates = CertificateUtil.extractCertificates(request);
		if (CollectionUtils.isNotEmpty(x509Certificates)) {
			try {
				x509Certificates.stream().forEach(certificate -> CertificateUtil.analyse(certificate));
			} catch (Exception e) {
				logger.warn("Failed to analyze X509 certificates: " + e.getMessage(), e);
			}
		} else {
			logger.info("No X509 certificates found in request");
		}
		chain.doFilter(request, response);
	}
}

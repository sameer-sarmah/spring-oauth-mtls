package northwind.filter;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

import org.apache.commons.collections4.CollectionUtils;
import org.springframework.web.filter.GenericFilterBean;

import northwind.util.CertificateUtil;

public class AfterX509AuthenticationFilter extends GenericFilterBean{
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

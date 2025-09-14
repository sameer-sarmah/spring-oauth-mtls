package northwind.oauth.converter;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.apache.commons.collections4.CollectionUtils;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import northwind.util.CertificateUtil;
import northwind.util.HttpUtil;

@Component
public final class X509ClientCertificateAuthenticationConverter implements AuthenticationConverter {
	private static final ClientAuthenticationMethod TLS_CLIENT_AUTH_AUTHENTICATION_METHOD =
			new ClientAuthenticationMethod("tls_client_auth");

	@Nullable
	@Override
	public Authentication convert(HttpServletRequest request) {
		List<X509Certificate> clientCertificates = CertificateUtil.extractCertificates(request);
		if (CollectionUtils.isEmpty(clientCertificates)) {
			return null;
		}

		MultiValueMap<String, String> parameters = HttpUtil.getParameters(request);

		// client_id (REQUIRED)
		String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
		if (!StringUtils.hasText(clientId)) {
			return null;
		}

		if (parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}

		Map<String, Object>  additionalParameters = new HashMap<>(parameters.toSingleValueMap());
		additionalParameters.remove(OAuth2ParameterNames.CLIENT_ID);
		X509Certificate clientCertificate = clientCertificates.get(0);
		return new OAuth2ClientAuthenticationToken(
				clientId, TLS_CLIENT_AUTH_AUTHENTICATION_METHOD,
				clientCertificate, additionalParameters);
	}



}

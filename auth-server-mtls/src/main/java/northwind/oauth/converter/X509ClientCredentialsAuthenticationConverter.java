package northwind.oauth.converter;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import northwind.util.HttpUtil;

public class X509ClientCredentialsAuthenticationConverter implements AuthenticationConverter{
	private static final ClientAuthenticationMethod TLS_CLIENT_AUTH_AUTHENTICATION_METHOD =
			new ClientAuthenticationMethod("tls_client_auth");

	
	@Nullable
	@Override
	public Authentication convert(HttpServletRequest request) {
		// Attempt to extract client certificate
		X509Certificate clientCertificate = HttpUtil.extractClientCertificate(request);
		if (clientCertificate == null) {
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
		String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
		if (StringUtils.hasText(scope) &&
				parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}
		Set<String> requestedScopes = null;
		if (StringUtils.hasText(scope)) {
			requestedScopes = new HashSet<>(
					Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
		}
		Map<String, Object>  additionalParameters = new HashMap<>(parameters.toSingleValueMap());
		additionalParameters.remove(OAuth2ParameterNames.CLIENT_ID);
		var clientPrincipal = new OAuth2ClientAuthenticationToken(
				clientId, TLS_CLIENT_AUTH_AUTHENTICATION_METHOD,
				clientCertificate, additionalParameters);
		return new OAuth2ClientCredentialsAuthenticationToken(
				clientPrincipal, requestedScopes, additionalParameters);
	}

}

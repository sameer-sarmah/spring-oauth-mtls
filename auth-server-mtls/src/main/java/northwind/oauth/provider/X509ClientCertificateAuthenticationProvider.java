package northwind.oauth.provider;

import java.security.cert.X509Certificate;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

@Component
public final class X509ClientCertificateAuthenticationProvider implements AuthenticationProvider {
	private static final ClientAuthenticationMethod TLS_CLIENT_AUTH_AUTHENTICATION_METHOD =
			new ClientAuthenticationMethod("tls_client_auth");
	private final RegisteredClientRepository registeredClientRepository;

	public X509ClientCertificateAuthenticationProvider(RegisteredClientRepository registeredClientRepository) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		this.registeredClientRepository = registeredClientRepository;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2ClientAuthenticationToken clientAuthentication =
				(OAuth2ClientAuthenticationToken) authentication;

		if (!TLS_CLIENT_AUTH_AUTHENTICATION_METHOD.equals(clientAuthentication.getClientAuthenticationMethod())) {
			return null;
		}

		String clientId = clientAuthentication.getPrincipal().toString();
		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
		if (registeredClient == null) {
			throwInvalidClient();
		}

		if (!registeredClient.getClientAuthenticationMethods().contains(
				clientAuthentication.getClientAuthenticationMethod())) {
			throwInvalidClient();
		}

		if (!(clientAuthentication.getCredentials() instanceof X509Certificate)) {
			throwInvalidClient();
		}

		X509Certificate x509Certificate = (X509Certificate) clientAuthentication.getCredentials();
		String subjectDN = x509Certificate.getSubjectDN().getName();
		if (!StringUtils.hasText(subjectDN) ||
				!subjectDN.equals(registeredClient.getClientSettings().getSetting("SubjectDN"))) {
			throwInvalidClient();
		}

		return new OAuth2ClientAuthenticationToken(registeredClient,
				clientAuthentication.getClientAuthenticationMethod(), x509Certificate);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
	}



	private static void throwInvalidClient() {
		throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
	}

}
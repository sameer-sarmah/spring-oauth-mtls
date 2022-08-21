package northwind.oauth.converter;

import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ClientCredentialsAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public final class ResourceValidatingAuthenticationConverter implements AuthenticationConverter {

	private final AuthenticationConverter defaultAuthenticationConverter =
			new DelegatingAuthenticationConverter(
				Arrays.asList(
					new X509ClientCredentialsAuthenticationConverter(),
					new OAuth2ClientCredentialsAuthenticationConverter()
				)
			);

	private final List<String> acceptedResourceIds = Arrays.asList("https://127.0.0.1:8443/products");

	@Nullable
	@Override
	public Authentication convert(HttpServletRequest request) {
		String resource = request.getParameter("resource");
		if (StringUtils.hasText(resource) &&
				!this.acceptedResourceIds.contains(resource)) {

			throw new OAuth2AuthenticationException("invalid_target");
		}

		return this.defaultAuthenticationConverter.convert(request);
	}

}
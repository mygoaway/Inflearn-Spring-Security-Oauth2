package study.inflearn.security.Oauth2.filter;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;

public class CustomOAuth2AuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public static final String DEFAULT_FILTER_PROCESSING_URI = "/oauth2Login/**";

    private DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;
    private OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;
    private OAuth2AuthorizationSuccessHandler oAuth2AuthorizationSuccessHandler;

    private Duration clockSkew = Duration.ofSeconds(3600);

    private Clock clock = Clock.systemUTC();

    public CustomOAuth2AuthenticationFilter(
            DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager,
            OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository
    ) {
        super(DEFAULT_FILTER_PROCESSING_URI);
        this.oAuth2AuthorizedClientManager = oAuth2AuthorizedClientManager;
        this.oAuth2AuthorizedClientRepository = oAuth2AuthorizedClientRepository;

        this.oAuth2AuthorizationSuccessHandler = (authorizedClient, principal, attributes) -> {
            oAuth2AuthorizedClientRepository.saveAuthorizedClient(authorizedClient, principal,
                    (HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
                    (HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));
            System.out.println("authorizedClient = " + authorizedClient);
            System.out.println("principal = " + principal);
            System.out.println("attributes = " + attributes);
        };
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                .withClientRegistrationId("keycloak")
                .principal(authentication)
                .attribute(HttpServletRequest.class.getName(), request)
                .attribute(HttpServletResponse.class.getName(), response)
                .build();


        OAuth2AuthorizedClient authorizedClient = oAuth2AuthorizedClientManager.authorize(authorizeRequest);

        // 권한 부여 타입을 변경하지 않고 토큰 재발금
        if (authorizedClient != null && hasTokenExpired(authorizedClient.getAccessToken())
                && authorizedClient.getRefreshToken() != null) {
            authorizedClient = oAuth2AuthorizedClientManager.authorize(authorizeRequest);
        }


        if (authorizedClient != null) {
            ClientRegistration clientRegistration = ClientRegistration.withClientRegistration
                            (authorizedClient.getClientRegistration()).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .build();

            OAuth2AuthorizedClient oAuth2AuthorizedClient =
                    new OAuth2AuthorizedClient(clientRegistration, authorizedClient.getPrincipalName(),
                            authorizedClient.getAccessToken(), authorizedClient.getRefreshToken());

            OAuth2AuthorizeRequest oAuth2AuthorizeRequest =
                    OAuth2AuthorizeRequest.withAuthorizedClient(oAuth2AuthorizedClient)
                            .principal(authentication)
                            .attribute(HttpServletRequest.class.getName(), request)
                            .attribute(HttpServletResponse.class.getName(), response)
                            .build();

            authorizedClient = oAuth2AuthorizedClientManager.authorize(oAuth2AuthorizeRequest);
        }


        return null;

    }

    private boolean hasTokenExpired(OAuth2Token token) {
        return this.clock.instant().isAfter(token.getExpiresAt().minus(this.clockSkew));
    }
}

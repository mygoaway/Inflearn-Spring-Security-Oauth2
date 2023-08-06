package study.inflearn.security.Oauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;

@Configuration
public class OAuth2ClientConfig {

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(keyCloakClientRegistration());
    }

    private ClientRegistration keyCloakClientRegistration() {
        return ClientRegistrations.fromIssuerLocation("http://localhost:8080/realms/oauth2")
                .registrationId("keycloakManual")
                .clientId("oauth2-client-app")
                .clientSecret("TCUwfHOUaTMdovquaEOeG8H4pZah7X6q")
                .redirectUri("http://localhost:8081/login/oauth2/code/keycloak")
                .build();
    }
}

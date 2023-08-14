package study.inflearn.security.Oauth2;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@EnableWebSecurity
@RequiredArgsConstructor
public class OAuth2ClientConfig {

    private final ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeRequests(request -> request.antMatchers("/login").permitAll()
                .anyRequest().authenticated());
        httpSecurity.oauth2Login(oauth2 -> oauth2.loginPage("/login")
                //.loginProcessingUrl("/login/v1/oauth2/code")
                .authorizationEndpoint(authorizationEndpointConfig ->
                        authorizationEndpointConfig.baseUri("/oauth2/v1/authorization"))
                .redirectionEndpoint(redirectionEndpointConfig ->
                        redirectionEndpointConfig.baseUri("/login/v1/oauth2/code"))); // 인가서버 redirect 수정해야함


        return httpSecurity.build();
    }
}

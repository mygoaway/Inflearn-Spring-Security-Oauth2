package study.inflearn.security.Oauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class OAuth2ClientConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        //httpSecurity.authorizeRequests().anyRequest().authenticated();
        httpSecurity.authorizeRequests(authRequest -> authRequest
                //.antMatchers("/loginPage")
                //.permitAll()
                .anyRequest().authenticated());
        httpSecurity.oauth2Login(Customizer.withDefaults());
        //httpSecurity.oauth2Login(oauth2 -> oauth2.loginPage("/loginPage"));
        return httpSecurity.build();
    }
}

package study.inflearn.security.Oauth2.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;

@Controller
@RequiredArgsConstructor
public class ClientController {
    private final OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;
    private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;


    @GetMapping("/client")
    public String client(HttpServletRequest request, Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        String clientRegistrationId = "keycloak";
        OAuth2AuthorizedClient oAuth2AuthorizedClient = oAuth2AuthorizedClientRepository.loadAuthorizedClient(clientRegistrationId, authentication, request);
        OAuth2AuthorizedClient oAuth2AuthorizedClient1 = oAuth2AuthorizedClientService.loadAuthorizedClient(clientRegistrationId, authentication.getName());

        System.out.println("oAuth2AuthorizedClient = " + oAuth2AuthorizedClient);
        System.out.println("oAuth2AuthorizedClient1 = " + oAuth2AuthorizedClient1);

        OAuth2AccessToken accessToken = oAuth2AuthorizedClient.getAccessToken();

        OAuth2UserService oAuth2UserService = new DefaultOAuth2UserService();
        OAuth2User oauth2User = oAuth2UserService.loadUser(new OAuth2UserRequest(oAuth2AuthorizedClient.getClientRegistration(), accessToken));

        OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken
                (oauth2User, Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")), clientRegistrationId);

        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        model.addAttribute("accessToken", oAuth2AuthorizedClient.getAccessToken().getTokenValue());
        model.addAttribute("refreshToken", oAuth2AuthorizedClient.getRefreshToken().getTokenValue());
        model.addAttribute("principalName", oauth2User.getName());
        model.addAttribute("clientName", oAuth2AuthorizedClient.getClientRegistration().getClientName());

        return "client";
    }
}

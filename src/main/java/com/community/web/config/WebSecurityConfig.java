package com.community.web.config;

import com.community.web.domain.enums.SocialType;
import com.community.web.oauth.CustomOAuth2Provider;
import org.springframework.beans.factory.annotation.CustomAutowireConfigurer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.filter.CharacterEncodingFilter;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity // 웹시큐리티 사용하겠다는 어노테이션
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        CharacterEncodingFilter filter = new CharacterEncodingFilter();

        http.authorizeRequests()
                .antMatchers("/", "/oauth2/**", "/login/**", "/css/**", "/images/**", "/js/**", "/console/**")
                    .permitAll() // index, login, static resources는 접근 허용
                .antMatchers("/facebook")
                    .hasAnyAuthority(SocialType.FACEBOOK.getRoleType())
                .antMatchers("/google")
                    .hasAnyAuthority(SocialType.GOOGLE.getRoleType())
                .antMatchers("/kakao")
                    .hasAnyAuthority(SocialType.KAKAO.getRoleType())
                .anyRequest()
                    .authenticated()
            .and()
                .oauth2Login()
                    .defaultSuccessUrl("/loginSuccess")
                    .failureUrl("/loginFailure")
            .and()
                .headers() // 응답 header 설정
                    .frameOptions().disable() // XFrameOptionsHeaderWriter의 최적화 설정을 허용하지 않음
            .and()
                .exceptionHandling()
                    .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")) // 인증되지 않은 사용자가 인증이 필요한 경로 접근 시 해당 URI로 이동시킴
            .and()
                .formLogin()
                    .successForwardUrl("/board/list") // 로그인 성공 시 포워딩 될 URI
            .and()
                .logout()
                    .logoutUrl("/logout") // 로그아웃이 수행될 URL
                    .logoutSuccessUrl("/") // 로그아웃 성공 시 포워딩될 URI
                    .deleteCookies("JSESSIONID") // JSESSIONID 삭제
                    .invalidateHttpSession(true) // 세션 invalidate
            .and()
                .addFilterBefore(filter, CsrfFilter.class) // 문자 인코딩 필터 전에 CsrfFilter 적용
                .csrf().disable();
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(
            OAuth2ClientProperties oAuth2ClientProperties,
            @Value("${custom.oauth2.kakao.client-id}") String kakaoClientId) { // application.yml 에 설정한 kakao client-id를 불러옴

        // 기본 제공 OAuth2 인증 정보 빌드한 결과를 List로 collect
        List<ClientRegistration> registrationList =
                oAuth2ClientProperties.getRegistration().keySet().stream()
                .map(client -> getRegistration(oAuth2ClientProperties, client))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        // 커스텀 OAuth2 인증 정보 빌드한 결과를 위 list에 추가
        registrationList.add(CustomOAuth2Provider.KAKAO.getBuilder("kakao")
            .clientId(kakaoClientId)
            .clientSecret("test")
            .jwkSetUri("test")
            .build());

        return new InMemoryClientRegistrationRepository(registrationList);
    }

    private ClientRegistration getRegistration (OAuth2ClientProperties oAuth2ClientProperties, String client) {
        if ("google".equals(client)) {
            OAuth2ClientProperties.Registration registration =
                    oAuth2ClientProperties.getRegistration().get("google");

            return CommonOAuth2Provider.GOOGLE.getBuilder(client)
                    .clientId(registration.getClientId())
                    .clientSecret(registration.getClientSecret())
                    .scope("email", "profile")
                    .build();
        }

        if ("facebook".equals(client)) {
            OAuth2ClientProperties.Registration registration =
                    oAuth2ClientProperties.getRegistration().get("facebook");

            return CommonOAuth2Provider.FACEBOOK.getBuilder(client)
                    .clientId(registration.getClientId())
                    .clientSecret(registration.getClientSecret())
                    // 페북의 graph API는 scope로는 필요한 필드를 반환해주지 않아 idm name, email, link를 파라미터로 넣어 요청하도록 설정
                    .userInfoUri("https://graph.facebook.com/me?fields=id,name,email,link")
                    .scope("email")
                    .build();
        }

        return null;
    }
}

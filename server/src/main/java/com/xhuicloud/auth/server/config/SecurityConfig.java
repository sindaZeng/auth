package com.xhuicloud.auth.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import javax.sql.DataSource;
import java.util.UUID;

import static org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType.H2;

@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http
                .exceptionHandling((exceptions) -> exceptions
                        .authenticationEntryPoint(
                                new LoginUrlAuthenticationEntryPoint("/login")) // 配置异常处理, 将重定向到登录页
                );

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("messaging-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope(OidcScopes.OPENID)
                .scope("message.read")
                .scope("message.write")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    /**
     * 协议端点的 URI
     *
     * @return
     */
    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder().issuer("http://localhost:4000").build();
    }

    /**
     * 用于身份验证的 Spring Security 过滤器链。
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated())
//                .formLogin(form -> form.loginPage("/login") // 自定义表单
//                        .permitAll())
                .formLogin(Customizer.withDefaults()) // 默认的表单登录
                //.httpBasic(withDefaults()) // 默认情况下，httpBasic默认启用。但是，一旦提供了任何基于 servlet 的配置，就必须显式提供 HTTP Basic。
//                .securityContext((securityContext) -> securityContext
//                        .securityContextRepository(new RequestAttributeSecurityContextRepository())
//                        .requireExplicitSave(true))
//                .securityContext().disable()

                .sessionManagement(session -> session
//                        .sessionCreationPolicy(SessionCreationPolicy.ALWAYS) // 预创建 session
//                        .invalidSessionUrl("/invalidSession.html") // 检测无效session后重定向 可能存在无效cookie 重复提交。 需要显式的删除 JSESSIONID Cookie
                                .maximumSessions(1) // 防止用户多次登录 - 第二次登录将导致第一次登录无效
                                .maxSessionsPreventsLogin(true) // 阻止第二次登录
                )
                .logout(logout -> logout
                        .deleteCookies("JSESSIONID"))

                .csrf(csrf -> csrf.disable()); // 禁用CSRF
        return http.build();
    }

    /**
     * 设置数据源
     *
     * @return
     */
    @Bean
    DataSource dataSource() {
        return new EmbeddedDatabaseBuilder()
                .setType(H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }

    /**
     * 初始化用户
     *
     * @param dataSource
     * @return
     */
    @Bean
    UserDetailsManager users(DataSource dataSource) {
        UserDetails user = User.builder()
                .username("user")
                .passwordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder()::encode)
                .password("user")
                .roles("USER")
                .build();
        UserDetails admin = User.builder()
                .username("admin")
                .passwordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder()::encode)
                .password("admin")
                .roles("USER", "ADMIN")
                .build();
        JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
        users.createUser(user);
        users.createUser(admin);
        return users;
    }

}

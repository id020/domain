package com.example.certmgr.config;

import com.example.certmgr.service.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security 安全配置。
 *
 * <p>核心职责：
 * ① 使用 {@link BCryptPasswordEncoder} 进行密码编码与校验；
 * ② 通过 {@link DaoAuthenticationProvider} 接入自定义 {@link UserDetailsServiceImpl}；
 * ③ 表单登录 + 退出登录；
 * ④ 除登录页、静态资源、ACME 挑战目录外，所有请求均需认证。</p>
 */
@Configuration
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    /** 自定义用户详情服务 */
    private final UserDetailsServiceImpl userDetailsService;

    /**
     * 密码编码器：BCrypt（自带加盐，每次加密结果不同但可正确校验）。
     *
     * @return BCrypt 密码编码器
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 认证提供者：将“用户详情服务 + 密码编码器”组合起来交给 Spring Security。
     *
     * @return DAO 认证提供者
     */
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    /**
     * 安全过滤链：定义路由放行规则与登录/登出行为。
     *
     * @param http HttpSecurity 构建器
     * @return 安全过滤链
     * @throws Exception 配置异常
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // 路由授权：明确放行的资源，其余全部要求登录（仪表盘 / 也需登录）
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/logout", "/error").permitAll()
                .requestMatchers("/css/**", "/js/**", "/images/**").permitAll()
                // ACME HTTP-01 挑战文件需对外公开，供 Let's Encrypt 校验器抓取
                .requestMatchers("/.well-known/**").permitAll()
                .anyRequest().authenticated()
            )
            // 表单登录：使用自定义登录页 /login
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/", true)
                .permitAll()
            )
            // 退出登录：POST /logout，成功后回到登录页
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .permitAll()
            );
        // 保留默认 CSRF 保护：所有页面表单均使用 th:action，Thymeleaf 会自动注入 CSRF 令牌
        return http.build();
    }
}

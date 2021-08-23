package com.nowcoder.community.config;

import com.nowcoder.community.entity.User;
import com.nowcoder.community.service.UserService;
import com.nowcoder.community.util.CommunityUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private UserService userService;

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/resources/**"); // 忽略静态资源访问，提高性能
    }

    /*
    AuthenticationManager: 认证的核心接口
    AuthenticationManagerBuilder: 用于构建AuthenticationManager对象
    ProviderManager: AuthenticationManager接口的默认实现类
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 内置认证规则
//        auth.userDetailsService(userService).passwordEncoder(new Pbkdf2PasswordEncoder("12345")); // salt
        /*
         自定义认证规则
         AuthenticationProvider: ProviderManager持有一组AuthenticationProvider，每个AuthenticationProvider负责一种认证（多种认证方式）
         委托模式：ProviderManager将认证委托给AuthenticationProvider
         */
        auth.authenticationProvider(new AuthenticationProvider() {
            // Authentication: 用于封装认证信息的接口，不同的实现类代表不同类型的认证信息
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                String username = authentication.getName();
                String password = (String) authentication.getCredentials();
                User user = userService.findUserByName(username);
                if (user == null) {
                    throw new UsernameNotFoundException("账号不存在！");
                }
                password = CommunityUtil.md5(password + user.getSalt());
                if (!user.getPassword().equals(password)) {
                    throw new BadCredentialsException("密码错误！");
                }

                // principal:主要信息，credentials：证书，authorities：权限
                return new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());
            }

            // 支持哪种类型的认证，我们只支持简单的密码认证UsernamePasswordAuthenticationToken
            @Override
            public boolean supports(Class<?> authentication) {
                return UsernamePasswordAuthenticationToken.class.equals(authentication);
            }
        });
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 登录相关配置
        http.formLogin()
                .loginPage("/loginpage")
                .loginProcessingUrl("/login")
                .successHandler((request, response, authentication) ->
                        response.sendRedirect(request.getContextPath() + "/index"))
                .failureHandler((request, response, e) -> {
                    request.setAttribute("error", e.getMessage());
                    request.getRequestDispatcher("/loginpage").forward(request, response);
                });

        // 退出相关配置
        http.logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler((request, response, authentication) -> {
                    response.sendRedirect(request.getContextPath() + "/index");
                });

        // 授权配置
        http.authorizeRequests()
                .antMatchers("/letter").hasAnyAuthority("USER", "ADMIN")
                .antMatchers("/admin").hasAnyAuthority("ADMIN")
                .and().exceptionHandling().accessDeniedPage("/denied");

        // 增加filter,在账号密码验证filter前调用（验证验证码）
        http.addFilterBefore((request, response, filterChain) -> {
            HttpServletRequest httpServletRequest = (HttpServletRequest) request;
            HttpServletResponse httpServletResponse = (HttpServletResponse) response;
            if (httpServletRequest.getServletPath().equals("/login")) {
                String verifyCode = request.getParameter("verifyCode");
                if (verifyCode == null || !verifyCode.equalsIgnoreCase("1234")) {
                    request.setAttribute("error", "验证码错误");
                    request.getRequestDispatcher("/loginpage").forward(request, response);
                    return;
                }
            }

            filterChain.doFilter(request, response); // 请求继续向下执行!!!没有这个，请求无法到达controller
        }, UsernamePasswordAuthenticationFilter.class);

        // 记住我
        http.rememberMe()
                .tokenRepository(new InMemoryTokenRepositoryImpl()) // 存在内存
                .tokenValiditySeconds(3600 * 24)
                .userDetailsService(userService);
    }
}

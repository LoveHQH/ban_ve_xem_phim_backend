package mflix.config;

import mflix.api.security.JWTAuthEntryPoint;
import mflix.api.security.JWTAuthenticationFilter;
import mflix.api.services.TokenAuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Autowired private JWTAuthEntryPoint unauthorizedHandler;

  @Autowired private TokenAuthenticationService authService;

  private static final String[] AUTH_WHITELIST = {

    // -- swagger ui
    "/swagger-resources/**", "/swagger-ui.html", "/v2/api-docs", "/webjars/**"
  };

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication()
            .withUser("admin").password(passwordEncoder().encode("1")).roles("ADMIN");
  }

//  @Override
//  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//    auth.jdbcAuthentication()
//            .dataSource(dataSource)
//            .usersByUsernameQuery("select `user_name` as `username`, `password`, `status` as `enable` from `user` where `user_name`= ?")
//            .authoritiesByUsernameQuery("select `user`.`user_name` as `username`, `user_group`.`name` as `role` from `user_group` join `user` on `user`.`user_groupid` = `user_group`.`id` where `user_name` = ?")
//            .passwordEncoder(passwordEncoder());
//  }

  @Override
  protected void configure(final HttpSecurity http) throws Exception {
    JWTAuthenticationFilter authFilter = new JWTAuthenticationFilter();
    authFilter.setAuthService(authService);
    http.authorizeRequests().antMatchers("/").permitAll().antMatchers("/admin/**").hasRole("ADMIN")
        .and()
        .formLogin().loginPage("/login").defaultSuccessUrl("/").failureUrl("/login?error=true")
            .permitAll().and()
            .logout().logoutSuccessUrl("/login").invalidateHttpSession(true).permitAll().and()
            .exceptionHandling().accessDeniedPage("/403")
            .and().csrf()
        .disable();
//        .exceptionHandling()
//        .authenticationEntryPoint(unauthorizedHandler)
//        .and()
//        .sessionManagement()
//        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//        .and()
//        .authorizeRequests()
//        .antMatchers(HttpMethod.OPTIONS)
//        .permitAll()
//        .antMatchers(AUTH_WHITELIST)
//        .permitAll()
//        .antMatchers("/api/v1/movies/**")
//        .permitAll()
//        .antMatchers("/api/v1/schedule/**")
//        .permitAll()
//        .antMatchers("/")
//        .permitAll()
//        .antMatchers("/**/*.{js,html,css}")
//        .permitAll()
//        .antMatchers("/api/v1/user/login")
//        .permitAll()
//        .antMatchers("/api/v1/user/register")
//        .permitAll()
//        .antMatchers("/api/v1/user/make-admin")
//        .permitAll()
//        .antMatchers("/api/v1/booking/booking")
//        .permitAll()
//        .antMatchers("/api/v1/user/")
//        .authenticated()
//        .anyRequest()
//        .authenticated()
//        .and()
//        .addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class);
  }

  @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

//  @Override
//  public void configure(WebSecurity web) {
//    super.configure(web);
////        web.ignoring().antMatchers("/admin/books");
//  }

}

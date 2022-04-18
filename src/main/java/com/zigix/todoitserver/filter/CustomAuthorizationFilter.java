package com.zigix.todoitserver.filter;

import com.zigix.todoitserver.config.jwt.JwtTokenUtil;
import com.zigix.todoitserver.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    public static final String BEARER_PREFIX = "Bearer ";
    private final JwtTokenUtil jwtTokenUtil;
    private final UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String accessToken = getAccessTokenFromRequest(request);
        if (StringUtils.hasText(accessToken) &&
                jwtTokenUtil.validateJwt(accessToken) &&
                isAccessTokenType(accessToken)) {
            String username = jwtTokenUtil.getUsername(accessToken);
            UserDetails userDetails = userService.loadUserByUsername(username);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        }

        filterChain.doFilter(request, response);
    }

    private String getAccessTokenFromRequest(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(header) && header.startsWith(BEARER_PREFIX)) {
            return header.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    private boolean isAccessTokenType(String token) {
        return jwtTokenUtil.getTokenType(token).equals(JwtTokenUtil.ACCESS_TOKEN_NAME);
    }
}

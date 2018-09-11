package org.apache.shiro.web;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.AntPathMatcher;
import org.apache.shiro.util.PathDefinitionMatcher;
import org.apache.shiro.util.PatternMatcher;
import org.apache.shiro.web.config.PathDefinition;
import org.apache.shiro.web.config.ShiroFilterChainDefinition;

import javax.security.sasl.AuthenticationException;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created on  2017/8/30 14:35
 *
 * @author gejian
 */
public class OncePerRequestFilter implements Filter {
    private ShiroFilterChainDefinition filterChainDefinition;
    private PatternMatcher patternMatcher;

    public OncePerRequestFilter() {
    }

    public void setFilterChainDefinition(ShiroFilterChainDefinition filterChainDefinition) {
        this.filterChainDefinition = filterChainDefinition;
    }

    public OncePerRequestFilter(ShiroFilterChainDefinition filterChainDefinition) {
        this.filterChainDefinition = filterChainDefinition;
    }

    private String loginUrl = "/login.html";

    private Map<String, PathDefinition> pathDefinitionMap = new ConcurrentHashMap<String, PathDefinition>();

    /**
     * only absolute url supported
     * @param loginUrl absolute-login-url
     */
    public void setLoginUrl(String loginUrl) {
        if (loginUrl == null || !loginUrl.startsWith("/")) {
            throw new IllegalArgumentException("only absolute login url supported");
        }
        this.loginUrl = loginUrl;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        this.patternMatcher = new AntPathMatcher();
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        //login page, pass directly
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        filter(request, servletResponse);
        filterChain.doFilter(servletRequest, servletResponse);
    }

    private void filter(HttpServletRequest request, ServletResponse servletResponse) throws IOException {
        String contextPath = request.getContextPath();
        String requestURI = request.getRequestURI().substring(contextPath.length());
        if (requestURI.equals(loginUrl)) {
            return;
        }

        Map<String, String> chainMap = filterChainDefinition.getFilterChainMap();
        //chainMap not defined
        if (chainMap == null) {
            return;
        }

        // get first pattern matches the uri, else will be ignored even if matched
        String pattern = null;
        Set<String> patterns = chainMap.keySet();
        for (String p : patterns) {
            boolean matches = patternMatcher.matches(p, requestURI);
            if (matches) {
                pattern = chainMap.get(p);
                break;
            }
        }
        //no pattern matched
        if (pattern == null) {
            return;
        }

        PathDefinition pathDefinition = pathDefinitionMap.get(pattern);
        if (pathDefinition == null) {
            pathDefinition = PathDefinitionMatcher.getPathDefinition(pattern);
            pathDefinitionMap.put(pattern, pathDefinition);
        }

        //pattern no need authentication
        if (!pathDefinition.isAuthc()) {
            return;
        }

        Subject subject = SecurityUtils.getSubject();
        // checkAuthenticated
        boolean b = subject.isAuthenticated();
        // checkRoles
        if (b) {
            Set<String> roles = pathDefinition.getRoles();
            b = subject.hasRoles(roles);
        }
        // checkPerms
        if (b) {
            Set<String> perms = pathDefinition.getPerms();
            b = subject.isPermittedAll(perms);
        }

        // all checked
        if (b) {
            return;
        }

        // checked false, redirect
        String redirectUrl = pathDefinition.getRedirectUrl();
        if (redirectUrl != null && !redirectUrl.isEmpty()) {
            HttpServletResponse response = (HttpServletResponse) servletResponse;
            response.sendRedirect(contextPath + redirectUrl);
        } else if (loginUrl != null && !loginUrl.isEmpty()) {
            HttpServletResponse response = (HttpServletResponse) servletResponse;
            response.sendRedirect(contextPath + loginUrl);
        } else {
            throw new AuthenticationException("you are not allowed");
        }

    }

    @Override
    public void destroy() {

    }
}

package org.apache.shiro.web;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectHolder;
import org.apache.shiro.util.AntPathMatcher;
import org.apache.shiro.util.PatternMatcher;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * Created on  2017/8/30 14:35
 *
 * @author gejian
 */
public abstract class SecurityWebFilter implements Filter {
    private PatternMatcher patternMatcher;
    private Map<WebPathPattern, PathDefinition> pathMapping = Collections.emptyMap();
    private String loginUrl;

    /**
     * 设置权限定义
     * @return 权限定义
     */
    protected abstract Map<WebPathPattern, PathDefinition> configPathMapping();

    /**
     * 设置全局登录页面
     * @return 全局登录页面
     */
    protected abstract String configLoginUrl();

    @Override
    public void init(FilterConfig filterConfig) {
        this.patternMatcher = new AntPathMatcher();
        Map<WebPathPattern, PathDefinition> mapping = configPathMapping();
        if (mapping != null && !mapping.isEmpty()) {
            this.pathMapping = mapping;
        }
        String loginUrl = configLoginUrl();
        if (loginUrl != null && !loginUrl.startsWith("/")) {
            loginUrl = "/" + loginUrl;
        }
        this.loginUrl = loginUrl;
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

        //chainMap not defined
        if (pathMapping.isEmpty()) {
            return;
        }

        // get first pattern matches the uri, else will be ignored even if matched
        PathDefinition pathDefinition = null;
        Set<WebPathPattern> patterns = pathMapping.keySet();
        for (WebPathPattern wp : patterns) {
            // 过滤未匹配的请求方法
            String method = wp.getMethod();
            if (method != null && !method.isEmpty() && !method.equals(request.getMethod())) {
                continue;
            }

            // 匹配路径
            boolean matches = patternMatcher.matches(wp.getPathPattern(), requestURI);
            if (matches) {
                pathDefinition = pathMapping.get(wp);
                break;
            }
        }
        //no pattern matched
        if (pathDefinition == null) {
            return;
        }

        //pattern no need authentication
        if (!pathDefinition.isAuthc()) {
            return;
        }

        Subject subject = SubjectHolder.getSubject();
        // checkAuthenticated
        boolean b = subject.isAuthenticated();
        // checkRoles
        if (b) {
            String[] roles = pathDefinition.getRoles();
            b = subject.hasRoles(roles);
        }
        // checkPerms
        if (b) {
            String[] perms = pathDefinition.getPerms();
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
            throw new AuthenticationException();
        }

    }

    @Override
    public void destroy() {
    }
}

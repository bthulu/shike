package org.apache.shiro.web;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.AntPathMatcher;
import org.apache.shiro.util.PatternMatcher;
import org.apache.shiro.web.config.ShiroFilterChainDefinition;

import javax.security.sasl.AuthenticationException;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.Set;

/**
 * Created on  2017/8/30 14:35
 *
 * @author gejian
 */
public class OncePerRequestFilter implements Filter {
    private final ShiroFilterChainDefinition filterChainDefinition;
    private PatternMatcher patternMatcher;

    public OncePerRequestFilter(ShiroFilterChainDefinition filterChainDefinition) {
        this.filterChainDefinition = filterChainDefinition;
    }

    private String loginUrl = "/login.html";

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
        String contextPath = request.getServletContext().getContextPath();
        String requestURI = request.getRequestURI().substring(contextPath.length());
        if (requestURI.equals(loginUrl)) {
            filterChain.doFilter(request, servletResponse);
            return;
        }

        Map<String, String> chainMap = filterChainDefinition.getFilterChainMap();
        if (chainMap != null) {
            String pattern = null;
            Set<String> patterns = chainMap.keySet();
            for (String p : patterns) {
                boolean matches = patternMatcher.matches(p, requestURI);
                if (matches) {
                    pattern = chainMap.get(p);
                }
            }
            if (pattern != null && !pattern.startsWith("anon")) {
                String[] split = pattern.split("],");
                //逗号隔开的最后一条, 如果不包含中括号, 则作为权限失败时的跳转页面
                String redirect = null;
                if (split.length > 1) {
                    int lenLack1 = split.length - 1;
                    String last = split[lenLack1];
                    if (!last.contains("[")) {
                        redirect = last;
                        String[] dest = new String[lenLack1];
                        System.arraycopy(split, 0, dest, 0, lenLack1);
                        split = dest;
                    }
                }

                //确定是否具备所需权限
                Subject subject = SecurityUtils.getSubject();
                boolean b = subject.isAuthenticated();
                if (b) {//if logon, then verify roles and perms
                    try {
                        for (String s : split) {
                            int length = s.length();
                            if (length < 8) {
                                continue;
                            }
                            int i = s.indexOf("[");
                            if (i == -1 || i > length - 3) {
                                continue;
                            }
                            String type = s.substring(0, i);
                            String[] typeValues = s.substring(i + 1, length - 1).split(",");
                            if ("perms".equals(type)) {
                                if (typeValues.length == 1) {
                                    b = subject.isPermitted(typeValues[0]);
                                } else {
                                    b = subject.isPermittedAll(typeValues);
                                }
                            } else if ("roles".equals(type)) {
                                if (typeValues.length == 1) {
                                    b = subject.hasRole(typeValues[0]);
                                } else {
                                    b = subject.hasRoles(typeValues);
                                }
                            }
                            if (!b) {
                                break;
                            }
                        }
                    } catch (Throwable t) {
                        b = false;
                    }
                }

                if (!b) {
                    if (redirect != null) {
                        HttpServletResponse response = (HttpServletResponse) servletResponse;
                        response.sendRedirect(redirect);
                        return;
                    } else if (loginUrl != null) {
                        HttpServletResponse response = (HttpServletResponse) servletResponse;
                        response.sendRedirect(loginUrl);
                        return;
                    } else {
                        throw new AuthenticationException("you are not allowed");
                    }
                }
            }
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy() {

    }
}

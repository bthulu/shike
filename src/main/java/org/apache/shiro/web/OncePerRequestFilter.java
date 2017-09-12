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
import java.util.Arrays;
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

    private String redirectUrl = "login.html";

    public void setRedirectUrl(String redirectUrl) {
        this.redirectUrl = redirectUrl;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        this.patternMatcher = new AntPathMatcher();
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        Map<String, String> chainMap = filterChainDefinition.getFilterChainMap();
        if (chainMap != null) {
            HttpServletRequest request = (HttpServletRequest) servletRequest;
            String requestURI = request.getRequestURI();
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
                boolean b = true;
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
                        Subject subject = SecurityUtils.getSubject();
                        if ("authc".equals(type)) {
                            b = subject.isAuthenticated();
                        } else if ("perms".equals(type)) {
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

                if (!b) {
                    if (redirect != null) {
                        HttpServletResponse response = (HttpServletResponse) servletResponse;
                        response.sendRedirect(redirect);
                        return;
                    } else if (redirectUrl != null) {
                        HttpServletResponse response = (HttpServletResponse) servletResponse;
                        response.sendRedirect(redirectUrl);
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

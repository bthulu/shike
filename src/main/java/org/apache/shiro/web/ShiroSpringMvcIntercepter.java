package org.apache.shiro.web;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.annotation.Annotation;


public class ShiroSpringMvcIntercepter extends HandlerInterceptorAdapter {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        if (!(handler instanceof HandlerMethod)) {
            return true;
        }
        HandlerMethod method = (HandlerMethod) handler;
        Annotation[] declaredAnnotations = method.getMethod().getDeclaredAnnotations();
        RequiresAuthentication requiresAuthentication = null;
        RequiresPermissions requiresPermissions = null;
        RequiresRoles requiresRoles = null;
        for (Annotation declaredAnnotation : declaredAnnotations) {
            if (declaredAnnotation instanceof RequiresAuthentication) {
                requiresAuthentication = (RequiresAuthentication) declaredAnnotation;
            } else if (declaredAnnotation instanceof RequiresPermissions) {
                requiresPermissions = (RequiresPermissions) declaredAnnotation;
            } else if (declaredAnnotation instanceof RequiresRoles) {
                requiresRoles = (RequiresRoles) declaredAnnotation;
            }
        }

        //已登陆验证
        Subject subject = SecurityUtils.getSubject();
        if (requiresAuthentication != null) {
            boolean b = subject.isAuthenticated();
            if (!b) {
                throw new UnauthenticatedException();
            }
        }
        //权限验证
        if (requiresPermissions != null) {
            String[] value = requiresPermissions.value();
            Logical logical = requiresPermissions.logical();
            boolean b;
            if (Logical.AND == logical) {
                if (value.length == 1) {
                    b = subject.isPermitted(value[0]);
                } else {
                    b = subject.isPermittedAll(value);
                }
            } else {
                if (value.length == 1) {
                    b = subject.isPermitted(value[0]);
                } else {
                    b = subject.isAnyPermitted(value);
                }
            }
            if (!b) {
                throw new AuthorizationException("permission lack");
            }
        }
        //角色验证
        if (requiresRoles != null) {
            String[] value = requiresRoles.value();
            Logical logical = requiresRoles.logical();
            boolean b;
            if (Logical.AND == logical) {
                if (value.length == 1) {
                    b = subject.hasRole(value[0]);
                } else {
                    b = subject.hasRoles(value);
                }
            } else {
                if (value.length == 1) {
                    b = subject.hasRole(value[0]);
                } else {
                    b = subject.hasAnyRole(value);
                }
            }
            if (!b) {
                throw new AuthorizationException("role lack");
            }
        }

        return true;
    }

}

package org.apache.shiro.subject;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationException;

import javax.servlet.http.HttpSession;
import java.io.Serializable;
import java.util.Collection;

/**
 * the implement must be thread-safe, and only one instance per application, it will be set into SecurityUtils
 */
public interface Subject {
    String getSessionTokenKey();

    Serializable getPrincipal();

    boolean isPermitted(String permission);

    boolean isPermittedAll(String... perms);

    boolean isAnyPermitted(String... perms);

    void checkPermission(String permission) throws AuthorizationException;

    void checkPermissionAll(String... perms) throws AuthorizationException;

    void checkAnyPermission(String... perms) throws AuthorizationException;

    boolean hasRole(String roleIdentifier);

    boolean hasRoles(String... roleIdentifiers);

    boolean hasAnyRole(String... roleIdentifiers);

    void checkRole(String roleIdentifier) throws AuthorizationException;

    void checkRoles(String... roleIdentifiers) throws AuthorizationException;

    void checkAnyRole(String... roleIdentifiers) throws AuthorizationException;

    void login(AuthenticationToken token) throws AuthenticationException;

    boolean isAuthenticated();

    HttpSession getSession();

    void logout();
}
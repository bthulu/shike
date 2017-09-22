package org.apache.shiro.subject;

import org.apache.shiro.authz.AuthorizationException;

import javax.servlet.http.HttpSession;
import java.io.Serializable;
import java.util.Set;

/**
 * the implement must be thread-safe, and only one instance per application, it will be set into SecurityUtils
 */
public interface Subject<T extends Serializable> {
//    String getSessionTokenKey();

    Set<String> getRoles();

    Set<String> getRoles(T principal);

    Set<String> getPermits();

    Set<String> getPermits(T principal);

    T getPrincipal();

    boolean isPermitted(String permit);

    boolean isPermittedAll(String... perms);

    boolean isAnyPermitted(String... perms);

    void checkPermission(String permit) throws AuthorizationException;

    void checkPermissionAll(String... perms) throws AuthorizationException;

    void checkAnyPermission(String... perms) throws AuthorizationException;

    boolean hasRole(String roleIdentifier);

    boolean hasRoles(String... roleIdentifiers);

    boolean hasAnyRole(String... roleIdentifiers);

    void checkRole(String roleIdentifier) throws AuthorizationException;

    void checkRoles(String... roleIdentifiers) throws AuthorizationException;

    void checkAnyRole(String... roleIdentifiers) throws AuthorizationException;

    // 登陆功能留给用户自己处理, 保持最大的灵活性
//    Object login(AuthenticationToken token) throws AuthenticationException;

    boolean isAuthenticated();

    HttpSession getSession();

    void logout();
}
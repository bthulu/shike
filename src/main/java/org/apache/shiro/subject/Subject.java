package org.apache.shiro.subject;

import org.apache.shiro.authz.AuthorizationException;

import java.io.Serializable;
import java.util.Collection;
import java.util.Set;

/**
 * the implement must be thread-safe, and only one instance per application.
 * this instance will be set into SubjectHolder.
 * if extends from AbstractSubject, its default constructor has already done it.
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

    boolean isPermittedAll(Collection<String> perms);

    boolean isAnyPermitted(String... perms);

    boolean isAnyPermitted(Collection<String> perms);

    void checkPermission(String permit) throws AuthorizationException;

    void checkPermissionAll(String... perms) throws AuthorizationException;

    void checkPermissionAll(Collection<String> perms) throws AuthorizationException;

    void checkAnyPermission(String... perms) throws AuthorizationException;

    void checkAnyPermission(Collection<String> perms) throws AuthorizationException;

    boolean hasRole(String roleIdentifier);

    boolean hasRoles(String... roleIdentifiers);

    boolean hasRoles(Collection<String> roleIdentifiers);

    boolean hasAnyRole(String... roleIdentifiers);

    boolean hasAnyRole(Collection<String> roleIdentifiers);

    void checkRole(String roleIdentifier) throws AuthorizationException;

    void checkRoles(String... roleIdentifiers) throws AuthorizationException;

    void checkRoles(Collection<String> roleIdentifiers) throws AuthorizationException;

    void checkAnyRole(String... roleIdentifiers) throws AuthorizationException;

    void checkAnyRole(Collection<String> roleIdentifiers) throws AuthorizationException;

    // 登陆功能留给用户自己处理, 保持最大的灵活性
//    Object login(AuthenticationToken token) throws AuthenticationException;

    boolean isAuthenticated();

    /**
     * logout current principal
     */
    void logout();

    /**
     * logout the specified principal
     *
     * @param principal the principal to be logout
     */
    void logout(T principal);

    /**
     * logout the specified principals
     *
     * @param principals the principals to be logout
     */
    void logout(Collection<T> principals);
}
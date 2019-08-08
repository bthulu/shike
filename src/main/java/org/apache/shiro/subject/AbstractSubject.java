package org.apache.shiro.subject;

import org.apache.shiro.authz.AuthorizationException;

import java.io.Serializable;
import java.util.Collection;
import java.util.Set;

/**
 * Created on  2017/8/30 10:19
 *
 * @author gejian
 */
public abstract class AbstractSubject<T extends Serializable> implements Subject<T> {

    public AbstractSubject() {
        SubjectHolder.setSubject(this);
    }

    @Override
    public Set<String> getRoles() {
        T principal = getPrincipal();
        return getRoles(principal);
    }

    @Override
    public Set<String> getPermits() {
        T principal = getPrincipal();
        return getPermits(principal);
    }

    @Override
    public boolean isPermitted(String permission) {
        if (permission == null) {
            return true;
        }
        Set<String> permits = getPermits();
        return permits != null && permits.contains(permission);
    }

    @Override
    public boolean isPermittedAll(String... perms) {
        Set<String> permits = getPermits();
        return containsAll(permits, perms);
    }

    @Override
    public boolean isPermittedAll(Collection<String> perms) {
        Set<String> permits = getPermits();
        return containsAll(permits, perms);
    }

    @Override
    public boolean isAnyPermitted(String... perms) {
        Set<String> permits = getPermits();
        return containsAny(permits, perms);
    }

    @Override
    public boolean isAnyPermitted(Collection<String> perms) {
        Set<String> permits = getPermits();
        return containsAny(permits, perms);
    }

    @Override
    public void checkPermission(String permission) throws AuthorizationException {
        boolean permitted = isPermitted(permission);
        if (!permitted) {
            throw new AuthorizationException("permission lack");
        }
    }

    @Override
    public void checkPermissionAll(String... perms) throws AuthorizationException {
        boolean b = isPermittedAll(perms);
        if (!b) {
            throw new AuthorizationException("perms lack");
        }
    }

    @Override
    public void checkPermissionAll(Collection<String> perms) throws AuthorizationException {
        boolean b = isPermittedAll(perms);
        if (!b) {
            throw new AuthorizationException("perms lack");
        }
    }

    @Override
    public void checkAnyPermission(String... perms) throws AuthorizationException {
        boolean b = isAnyPermitted(perms);
        if (!b) {
            throw new AuthorizationException("permission lack");
        }
    }

    @Override
    public void checkAnyPermission(Collection<String> perms) throws AuthorizationException {
        boolean b = isAnyPermitted(perms);
        if (!b) {
            throw new AuthorizationException("permission lack");
        }
    }

    @Override
    public boolean hasRole(String roleIdentifier) {
        if (roleIdentifier == null) {
            return true;
        }
        Set<String> roles = getRoles();
        return roles != null && roles.contains(roleIdentifier);
    }

    @Override
    public boolean hasRoles(String... roleIdentifiers) {
        Set<String> roles = getRoles();
        return containsAll(roles, roleIdentifiers);
    }

    @Override
    public boolean hasRoles(Collection<String> roleIdentifiers) {
        Set<String> roles = getRoles();
        return containsAll(roles, roleIdentifiers);
    }

    @Override
    public boolean hasAnyRole(String... roleIdentifiers) {
        Set<String> roles = getRoles();
        return containsAny(roles, roleIdentifiers);
    }

    @Override
    public boolean hasAnyRole(Collection<String> roleIdentifiers) {
        Set<String> roles = getRoles();
        return containsAny(roles, roleIdentifiers);
    }

    @Override
    public void checkRole(String roleIdentifier) throws AuthorizationException {
        boolean hasRole = hasRole(roleIdentifier);
        if (!hasRole) {
            throw new AuthorizationException("role lack");
        }
    }

    @Override
    public void checkRoles(String... roleIdentifiers) throws AuthorizationException {
        boolean b = hasRoles(roleIdentifiers);
        if (!b) {
            throw new AuthorizationException("roles lack");
        }
    }

    @Override
    public void checkRoles(Collection<String> roleIdentifiers) throws AuthorizationException {
        boolean b = hasRoles(roleIdentifiers);
        if (!b) {
            throw new AuthorizationException("roles lack");
        }
    }

    @Override
    public void checkAnyRole(String... roleIdentifiers) throws AuthorizationException {
        boolean b = hasAnyRole(roleIdentifiers);
        if (!b) {
            throw new AuthorizationException("role lack");
        }
    }

    @Override
    public void checkAnyRole(Collection<String> roleIdentifiers) throws AuthorizationException {
        boolean b = hasAnyRole(roleIdentifiers);
        if (!b) {
            throw new AuthorizationException("role lack");
        }
    }

    @Override
    public void logout(T principal) {
        throw new UnsupportedOperationException("logout specified principal is not supported, you should implement it yourself");
    }

    @Override
    public void logout(Collection<T> principal) {
        throw new UnsupportedOperationException("logout specified principals is not supported, you should implement it yourself");
    }

    private boolean containsAny(Set<String> container, String... content) {
        if (content == null || content.length == 0) {
            return true;
        }
        if (container == null || container.isEmpty()) {
            return false;
        }
        for (String s : content) {
            if (container.contains(s)) {
                return true;
            }
        }
        return false;
    }

    private boolean containsAll(Set<String> container, String... content) {
        if (content == null || content.length == 0) {
            return true;
        }
        if (container == null || container.isEmpty()) {
            return false;
        }
        for (String s : content) {
            if (!container.contains(s)) {
                return false;
            }
        }
        return true;
    }

    private boolean containsAny(Set<String> container, Collection<String> content) {
        if (content == null || content.isEmpty()) {
            return true;
        }
        if (container == null || container.isEmpty()) {
            return false;
        }
        for (String s : content) {
            if (container.contains(s)) {
                return true;
            }
        }
        return false;
    }

    private boolean containsAll(Set<String> container, Collection<String> content) {
        if (content == null || content.isEmpty()) {
            return true;
        }
        if (container == null || container.isEmpty()) {
            return false;
        }
        return container.containsAll(content);
    }
}
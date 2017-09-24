package org.apache.shiro.subject;

import org.apache.shiro.authz.AuthorizationException;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Set;

/**
 * Created on  2017/8/30 10:19
 *
 * @author gejian
 */
public abstract class AbstractWebSubject<T extends Serializable> implements WebSubject<T> {

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
        if (perms == null || perms.length == 0) {
            return true;
        }
        Set<String> permits = getPermits();
        return permits != null && permits.containsAll(Arrays.asList(perms));
    }

    @Override
    public boolean isAnyPermitted(String... perms) {
        if (perms == null || perms.length == 0) {
            return true;
        }
        Set<String> permits = getPermits();
        if (permits != null) {
            for (String perm : perms) {
                if (permits.contains(perm)) {
                    return true;
                }
            }
        }
        return false;
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
    public void checkAnyPermission(String... perms) throws AuthorizationException {
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
        if (roleIdentifiers == null || roleIdentifiers.length == 0) {
            return true;
        }
        Set<String> roles = getRoles();
        return roles != null && roles.containsAll(Arrays.asList(roleIdentifiers));
    }

    @Override
    public boolean hasAnyRole(String... roleIdentifiers) {
        if (roleIdentifiers == null || roleIdentifiers.length == 0) {
            return true;
        }
        Set<String> roles = getRoles();
        if (roles != null) {
            for (String roleIdentifier : roleIdentifiers) {
                if (roles.contains(roleIdentifier)) {
                    return true;
                }
            }
        }
        return false;
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
    public void checkAnyRole(String... roleIdentifiers) throws AuthorizationException {
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
    public void logout(T... principal) {
        throw new UnsupportedOperationException("logout specified principals is not supported, you should implement it yourself");
    }
}
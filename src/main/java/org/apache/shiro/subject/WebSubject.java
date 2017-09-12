package org.apache.shiro.subject;

import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.Realm;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * Created on  2017/8/30 10:19
 *
 * @author gejian
 */
public abstract class WebSubject implements Subject {

    protected Realm realm;

    public WebSubject(Realm realm) {
        this.realm = realm;
    }

    @Override
    public boolean isPermitted(String permission) {
        Serializable principal = getPrincipal();
        if (principal == null) {
            return false;
        }
        AuthorizationInfo authorizationInfo = realm.doGetAuthorizationInfo(principal);
        Collection<Serializable> permissions = authorizationInfo.getPermissions();
        return permissions != null && permissions.contains(permission);
    }

    @Override
    public boolean isPermittedAll(String... perms) {
        Serializable principal = getPrincipal();
        if (principal == null) {
            return false;
        }
        AuthorizationInfo authorizationInfo = realm.doGetAuthorizationInfo(principal);
        Collection<Serializable> permissions = authorizationInfo.getPermissions();
        List<String> list = Arrays.asList(perms);
        return permissions != null && permissions.containsAll(list);
    }

    @Override
    public boolean isAnyPermitted(String... perms) {
        Serializable principal = getPrincipal();
        if (principal == null) {
            return false;
        }
        AuthorizationInfo authorizationInfo = realm.doGetAuthorizationInfo(principal);
        Collection<Serializable> permissions = authorizationInfo.getPermissions();
        if (permissions == null) {
            return false;
        }
        for (Serializable perm : perms) {
            if (permissions.contains(perm)) {
                return true;
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
        Serializable principal = getPrincipal();
        if (principal == null) {
            return false;
        }
        AuthorizationInfo authorizationInfo = realm.doGetAuthorizationInfo(principal);
        Collection<Serializable> roles = authorizationInfo.getRoles();
        return roles != null && roles.contains(roleIdentifier);
    }

    @Override
    public boolean hasRoles(String... roleIdentifiers) {
        Serializable principal = getPrincipal();
        if (principal == null) {
            return false;
        }
        AuthorizationInfo authorizationInfo = realm.doGetAuthorizationInfo(principal);
        Collection<Serializable> roles = authorizationInfo.getRoles();
        List<String> list = Arrays.asList(roleIdentifiers);
        return roles != null && roles.containsAll(list);
    }

    @Override
    public boolean hasAnyRole(String... roleIdentifiers) {
        Serializable principal = getPrincipal();
        if (principal == null) {
            return false;
        }
        AuthorizationInfo authorizationInfo = realm.doGetAuthorizationInfo(principal);
        Collection<Serializable> roles = authorizationInfo.getRoles();
        if (roles == null) {
            return false;
        }
        for (Serializable roleIdentifier : roleIdentifiers) {
            if (roles.contains(roleIdentifier)) {
                return true;
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
    public void logout() {
        getSession().invalidate();
    }

}

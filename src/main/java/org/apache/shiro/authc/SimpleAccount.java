package org.apache.shiro.authc;

import java.io.Serializable;
import java.util.Set;

/**
 * Created on  2017/8/30 10:48
 *
 * @author gejian
 */
public class SimpleAccount implements Account {

    private Serializable principal;

    private Serializable credential;

    private Set roles;

    private Set permissions;

    @Override
    public Serializable getPrincipal() {
        return principal;
    }

    public void setPrincipal(Serializable principal) {
        this.principal = principal;
    }

    @Override
    public Serializable getCredential() {
        return credential;
    }

    public void setCredential(Serializable credential) {
        this.credential = credential;
    }

    @Override
    public Set getRoles() {
        return roles;
    }

    public void setRoles(Set roles) {
        this.roles = roles;
    }

    @Override
    public Set getPermissions() {
        return permissions;
    }

    public void setPermissions(Set permissions) {
        this.permissions = permissions;
    }
}

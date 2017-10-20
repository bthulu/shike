package org.apache.shiro.web.config;

import java.util.Collections;
import java.util.Set;

/**
 * @author gejian at 2017/10/20 16:18
 */
public class PathDefinition {
    private boolean authc = false;
    private Set<String> roles = Collections.emptySet();
    private Set<String> perms = Collections.emptySet();
    private String redirectUrl = "";

    public boolean isAuthc() {
        return authc;
    }

    public void setAuthc(boolean authc) {
        this.authc = authc;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    public Set<String> getPerms() {
        return perms;
    }

    public void setPerms(Set<String> perms) {
        this.perms = perms;
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }

    public void setRedirectUrl(String redirectUrl) {
        this.redirectUrl = redirectUrl;
    }

    @Override
    public String toString() {
        return "PathDefinition{" +
                "authc=" + authc +
                ", roles=" + roles +
                ", perms=" + perms +
                ", redirectUrl='" + redirectUrl + '\'' +
                '}';
    }
}

package org.apache.shiro.web;

import java.util.Arrays;

/**
 * @author gejian at 2017/10/20 16:18
 */
public class PathDefinition {
    private boolean authc = false;
    private String[] roles = new String[0];
    private String[] perms = new String[0];
    private String redirectUrl = "";

    public boolean isAuthc() {
        return authc;
    }

    public void setAuthc(boolean authc) {
        this.authc = authc;
    }

    public String[] getRoles() {
        return roles;
    }

    public void setRoles(String[] roles) {
        if (roles != null) {
            this.roles = roles;
        }
    }

    public String[] getPerms() {
        return perms;
    }

    public void setPerms(String[] perms) {
        if (perms != null) {
            this.perms = perms;
        }
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }

    public void setRedirectUrl(String redirectUrl) {
        if (redirectUrl != null) {
            this.redirectUrl = redirectUrl;
        }
    }

    @Override
    public String toString() {
        return "PathDefinition{" +
                "authc=" + authc +
                ", roles=" + Arrays.toString(roles) +
                ", perms=" + Arrays.toString(perms) +
                ", redirectUrl='" + redirectUrl + '\'' +
                '}';
    }
}

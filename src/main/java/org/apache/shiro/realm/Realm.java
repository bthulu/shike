package org.apache.shiro.realm;

import org.apache.shiro.authz.AuthorizationInfo;

import java.io.Serializable;

public interface Realm {

    AuthorizationInfo doGetAuthorizationInfo(Serializable principal);

}
package org.apache.shiro.authc;

import org.apache.shiro.authz.AuthorizationInfo;

/**
 * Created on  2017/8/30 10:47
 *
 * @author gejian
 */
public interface Account extends AuthenticationInfo, AuthorizationInfo, AuthenticationToken {
}

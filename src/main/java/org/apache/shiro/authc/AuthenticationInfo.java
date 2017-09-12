package org.apache.shiro.authc;

import java.io.Serializable;

public interface AuthenticationInfo extends Serializable {

    Object getPrincipal();

    Object getCredential();

}

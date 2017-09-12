package org.apache.shiro.authc;

import java.io.Serializable;

public interface AuthenticationToken extends Serializable {

    Serializable getPrincipal();

    Serializable getCredential();

}
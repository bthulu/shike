package org.apache.shiro.authz;

import java.io.Serializable;
import java.util.Collection;

public interface AuthorizationInfo extends Serializable {

    Collection<Serializable> getRoles();

    Collection<Serializable> getPermissions();

}

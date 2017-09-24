package org.apache.shiro.subject;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;

public interface WebSubject<T extends Serializable> extends Subject<T> {

    T getPrincipal(HttpServletRequest request);

    /**
     * logout current principal, which can be retrieved from the request
     *
     * @param request from which current principal can be retrieved
     */
    void logout(HttpServletRequest request);
}
package org.apache.shiro.subject;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;

public interface WebSubject<T extends Serializable> extends Subject<T> {

    T getPrincipal(HttpServletRequest request);
}
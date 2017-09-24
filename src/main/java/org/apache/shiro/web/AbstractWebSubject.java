package org.apache.shiro.web;

import org.apache.shiro.subject.AbstractSubject;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.Serializable;

/**
 * Created on  2017/8/30 14:26
 *
 * @author gejian
 */
public abstract class AbstractWebSubject<T extends Serializable> extends AbstractSubject<T> implements WebSubject<T> {
    // used as the HttpServletRequest's attribute key for token
    private static final String TOKEN_KEY = "SMvcS_TOKEN_KEY";

    protected abstract HttpServletRequest getCurrentRequest();

    @Override
    public T getPrincipal() {
        return getPrincipal(getCurrentRequest());
    }

    @Override
    public boolean isAuthenticated() {
        return getPrincipal() != null;
    }

    /**
     * get token from request, if null, then get from session, and set to request
     */
    @SuppressWarnings("unchecked")
    public T getPrincipal(HttpServletRequest request) {
        T token = (T) request.getAttribute(TOKEN_KEY);
        if (token == null) {
            token = getPrincipal(request.getSession());
            request.setAttribute(TOKEN_KEY, token);
        }
        return token;
    }

    protected abstract T getPrincipal(HttpSession session);

    @Override
    public void logout() {
        logout(getCurrentRequest());
    }

    @Override
    public void logout(HttpServletRequest request) {
        request.getSession().invalidate();
    }
}

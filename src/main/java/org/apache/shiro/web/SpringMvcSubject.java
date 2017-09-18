package org.apache.shiro.web;

import org.apache.shiro.subject.WebSubject;
import org.springframework.beans.factory.annotation.Autowired;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.Serializable;

/**
 * Created on  2017/8/30 14:26
 *
 * @author gejian
 */
public abstract class SpringMvcSubject<T extends Serializable> extends WebSubject<T> {
    // used as the HttpServletRequest's attribute key for token
    private static final String TOKEN_KEY = "SMvcS_TOKEN_KEY";

    protected HttpServletRequest request;

    @Autowired
    public void setRequest(HttpServletRequest request) {
        this.request = request;
    }

    @Override
    public T getPrincipal() {
        return getPrincipal(request);
    }

    @Override
    public boolean isAuthenticated() {
        return getPrincipal() != null;
    }

    @Override
    public HttpSession getSession() {
        return request.getSession();
    }

    protected abstract T getPrincipal(HttpSession session);

    /**
     * get token from request, if null, then get from session, and set to request
     */
    @SuppressWarnings("unchecked")
    protected T getPrincipal(HttpServletRequest request) {
        T token = (T) request.getAttribute(TOKEN_KEY);
        if (token == null) {
            HttpSession session = request.getSession();
            token = getPrincipal(session);
            request.setAttribute(TOKEN_KEY, token);
        }
        return token;
    }
}

package org.apache.shiro.web;

import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.WebSubject;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.Serializable;

/**
 * Created on  2017/8/30 14:26
 *
 * @author gejian
 */
public abstract class SpringMvcSubject extends WebSubject {
    // used as the HttpServletRequest's attribute key for token
    private static final String TOKEN_KEY = "SMvcS_TOKEN_KEY";

    private HttpServletRequest request;

    public SpringMvcSubject(Realm realm, HttpServletRequest request) {
        super(realm);
        this.request = request;
    }

    @Override
    public Serializable getPrincipal() {
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

    protected abstract Serializable getPrincipal(HttpSession session);

    /**
     * get token from request, if null, then get from session, and set to request
     */
    public Serializable getPrincipal(HttpServletRequest request) {
        Serializable token = (Serializable) request.getAttribute(TOKEN_KEY);
        if (token == null) {
            HttpSession session = request.getSession();
            token = getPrincipal(session);
            request.setAttribute(TOKEN_KEY, token);
        }
        return token;
    }
}

package org.apache.shiro;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.ShiroSpringMvcInterceptor;

/**
 * Created on  2017/8/30 9:52
 * this subject is singleton, and no realms required. everything is done in subject.
 * for spring mvc, add {@link ShiroSpringMvcInterceptor} as spring mvc interceptor; for html, jsp, etc.., add {@link org.apache.shiro.web.OncePerRequestFilter} as servlet-filter
 *
 * @author gejian
 */
public abstract class SecurityUtils {

    private static Subject subject;

    public static void setSubject(Subject subject) {
        SecurityUtils.subject = subject;
    }

    public static Subject getSubject() {
        if (subject == null) {
            throw new ShiroException("subject can not be null");
        }
        return subject;
    }
}

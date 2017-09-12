package org.apache.shiro;

import org.apache.shiro.subject.Subject;

/**
 * Created on  2017/8/30 9:52
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

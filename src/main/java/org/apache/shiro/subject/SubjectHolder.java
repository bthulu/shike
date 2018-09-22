package org.apache.shiro.subject;

public class SubjectHolder {
    private static Subject subject;

    public static void setSubject(Subject subject) {
        if (subject == null) {
            throw new IllegalArgumentException("subject can not be null");
        }
        SubjectHolder.subject = subject;
    }

    public static Subject getSubject() {
        return subject;
    }
}

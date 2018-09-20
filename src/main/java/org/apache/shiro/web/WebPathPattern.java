package org.apache.shiro.web;

import java.util.Objects;

/**
 * web路径匹配
 */
public class WebPathPattern {
    private String method;
    private String pathPattern;

    /**
     * http请求方法
     */
    public String getMethod() {
        return method;
    }

    /**
     * http请求方法
     */
    public void setMethod(String method) {
        this.method = method;
    }

    /**
     * 匹配http url的ant pattern
     */
    public String getPathPattern() {
        return pathPattern;
    }

    /**
     * 匹配http url的ant pattern
     */
    public void setPathPattern(String pathPattern) {
        this.pathPattern = pathPattern;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WebPathPattern webPathPattern = (WebPathPattern) o;
        return Objects.equals(method, webPathPattern.method) &&
                Objects.equals(pathPattern, webPathPattern.pathPattern);
    }

    @Override
    public int hashCode() {
        return Objects.hash(method, pathPattern);
    }
}

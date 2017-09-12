package org.apache.shiro.web.config;

import java.util.Map;

/**
 * Created on  2017/8/30 14:38
 *
 * @author gejian
 */
public interface ShiroFilterChainDefinition {
    Map<String, String> getFilterChainMap();
}

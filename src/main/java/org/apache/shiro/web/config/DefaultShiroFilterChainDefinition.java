package org.apache.shiro.web.config;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created on  2017/8/30 14:39
 *
 * @author gejian
 */
public class DefaultShiroFilterChainDefinition implements ShiroFilterChainDefinition {
    public DefaultShiroFilterChainDefinition() {
        filterChainDefinitionMap = new LinkedHashMap<String, String>();
    }

    private final Map<String, String> filterChainDefinitionMap;

    public void addPathDefinition(String antPath, String definition) {
        filterChainDefinitionMap.put(antPath, definition);
    }

    public void addPathDefinitions(Map<String, String> pathDefinitions) {
        filterChainDefinitionMap.putAll(pathDefinitions);
    }

    @Override
    public Map<String, String> getFilterChainMap() {
        return filterChainDefinitionMap;
    }
}

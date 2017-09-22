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

    /**
     * The last string stands for redirect url, if not allowed to access, which will redirect to.
     * So, don't forget to give a anon to this redirect url at the last definitions. Or it will loop infinitely.
     *
     * @param antPath
     * @param definition
     */
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

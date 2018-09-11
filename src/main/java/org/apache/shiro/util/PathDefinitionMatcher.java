package org.apache.shiro.util;

import org.apache.shiro.web.config.PathDefinition;

import java.util.*;

/**
 * @author gejian at 2017/10/20 16:19
 */
public abstract class PathDefinitionMatcher {

    public static PathDefinition getPathDefinition(String pathPattern) {
        String[] split = pathPattern.split("],");
        List<String> list = new ArrayList<String>();
        for (String s1 : split) {
            int i = s1.indexOf('[');
            if (i != -1) {
                int i1 = s1.lastIndexOf(',', i);
                if (i1 != -1) {
                    String tmp = s1.substring(0, i - i1);
                    String[] split1 = tmp.split(",");
                    list.addAll(Arrays.asList(split1));
                    list.add(s1.substring(i - i1));
                } else {
                    list.add(s1);
                }

            } else {
                String[] split1 = s1.split(",");
                list.addAll(Arrays.asList(split1));
            }
        }
        PathDefinition pathDefinition = new PathDefinition();
        if (!list.isEmpty()) {
            int size = list.size();
            if (size > 1) {
                String last = list.get(size - 1);
                if (!last.contains("[")) {
                    pathDefinition.setRedirectUrl(last);
                    list.remove(size - 1);
                }
            }
            for (String s1 : list) {
                if (s1.startsWith("anon")) {
                    pathDefinition.setAuthc(false);
                    pathDefinition.setRoles(Collections.<String>emptySet());
                    pathDefinition.setPerms(Collections.<String>emptySet());
                    break;
                }
                if (s1.startsWith("authc")) {
                    pathDefinition.setAuthc(true);
                } else if (s1.startsWith("roles[")) {
                    pathDefinition.setAuthc(true);
                    if (s1.length() > 7) {
                        String[] roles = s1.substring(6).split(",");
                        Set<String> set = toSet(roles);
                        pathDefinition.setRoles(set);
                    }
                } else if (s1.startsWith("perms[")) {
                    pathDefinition.setAuthc(true);
                    if (s1.length() > 7) {
                        String[] perms = s1.substring(6).split(",");
                        Set<String> set = toSet(perms);
                        pathDefinition.setPerms(set);
                    }
                }
            }
        }
        return pathDefinition;
    }

    private static Set<String> toSet(String[] strings) {
        Set<String> set = new HashSet<String>((int) ((strings.length + 1) / 0.75f + 1));
        for (String s : strings) {
            if (s != null && !s.isEmpty()) {
                set.add(s);
            }
        }
        int size = set.size();
        switch (size) {
            case 0:
                return null;
            case 1:
                return Collections.singleton(set.iterator().next());
            default:
                return Collections.unmodifiableSet(set);
        }
    }
}

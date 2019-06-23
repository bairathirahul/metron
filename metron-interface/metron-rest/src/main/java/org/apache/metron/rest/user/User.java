/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.metron.rest.user;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import static org.apache.metron.rest.MetronRestConstants.SECURITY_ROLE_PREFIX;
import static org.apache.metron.rest.MetronRestConstants.SECURITY_ROLE_ADMIN;


public class User {
    public static List<String> getAuthorities() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication == null) {
            return null;
        }

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        return userDetails.getAuthorities().stream().map(ga -> ga.getAuthority()).collect(Collectors.toList());
    }

    public static boolean isAdmin() {
        List<String> authorities = User.getAuthorities();
        return authorities != null && authorities.contains(SECURITY_ROLE_PREFIX + SECURITY_ROLE_ADMIN);
    }

    public static List<String> getTenantIds() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication == null) {
            return null;
        }

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        return userDetails.getAuthorities().stream()
                .filter(ga -> ga.getAuthority().startsWith("TENANT_"))
                .map(ga -> ga.getAuthority().substring(7))
                .collect(Collectors.toList());
    }
}

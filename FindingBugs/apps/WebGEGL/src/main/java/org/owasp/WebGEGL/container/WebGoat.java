/**
 * ************************************************************************************************
 *
 * <p>
 *
 * <p>This file is part of WebGoat, an Open Web Application Security Project utility. For details,
 * please see http://www.owasp.org/
 *
 * <p>Copyright (c) 2002 - 2014 Bruce Mayhew
 *
 * <p>This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * <p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * <p>You should have received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * <p>Getting Source ==============
 *
 * <p>Source for this application is maintained at https://github.com/WebGoat/WebGoat, a repository
 * for free software projects.
 *
 * @author WebGoat
 * @version $Id: $Id
 * @since October 28, 2003
 */
package org.owasp.WebGEGL.container;

import java.io.File;

import org.owasp.WebGEGL.container.session.UserSessionData;
import org.owasp.WebGEGL.container.session.WebSession;
import org.owasp.WebGEGL.container.users.UserRepository;
import org.owasp.WebGEGL.container.users.WebGoatUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.web.client.RestTemplate;

@Configuration
@ComponentScan(basePackages = {"org.owasp.webgoat.container", "org.owasp.webgoat.lessons"})
@PropertySource("classpath:application-webgoat.properties")
@EnableAutoConfiguration
public class WebGoat {

  @Autowired private UserRepository userRepository;

  @Bean(name = "pluginTargetDirectory")
  public File pluginTargetDirectory(@Value("${webgoat.user.directory}") final String webgoatHome) {
    return new File(webgoatHome);
  }

  @Bean
  @Scope(value = "session", proxyMode = ScopedProxyMode.TARGET_CLASS)
  public WebSession webSession() {
    WebGoatUser webGoatUser = null;
    Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    if (principal instanceof WebGoatUser) {
      webGoatUser = (WebGoatUser) principal;
    } else if (principal instanceof DefaultOAuth2User) {
      webGoatUser = userRepository.findByUsername(((DefaultOAuth2User) principal).getName());
    }
    return new WebSession(webGoatUser);
  }

  @Bean
  @Scope(value = "session", proxyMode = ScopedProxyMode.TARGET_CLASS)
  public UserSessionData userSessionData() {
    return new UserSessionData("test", "data");
  }

  @Bean
  public RestTemplate restTemplate() {
    return new RestTemplate();
  }
}

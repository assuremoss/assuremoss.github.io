package org.owasp.WebGEGL.container.users;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;

/**
 * @author nbaars
 * @since 8/15/17.
 */
@Getter
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserSession {

  private WebGoatUser webGoatUser;
  @Id private String sessionId;
}

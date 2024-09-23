package org.owasp.WebGEGL.container.users;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.List;
import java.util.function.Function;
import lombok.AllArgsConstructor;
import org.flywaydb.core.Flyway;
import org.owasp.WebGEGL.container.lessons.Initializeable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * @author nbaars
 * @since 3/19/17.
 */
@Service
@AllArgsConstructor
public class UserService implements UserDetailsService {

  private final UserRepository userRepository;
  private final UserTrackerRepository userTrackerRepository;
  private final JdbcTemplate jdbcTemplate;
  private final Function<String, Flyway> flywayLessons;
  private final List<Initializeable> lessonInitializables;
  private final Connection targetConnection;

  @Override
  public WebGoatUser loadUserByUsername(String username) throws UsernameNotFoundException {
    WebGoatUser webGoatUser = userRepository.findByUsername(username);
    if (webGoatUser == null) {
      throw new UsernameNotFoundException("User not found");
    } else {
      webGoatUser.createUser();
      lessonInitializables.forEach(l -> l.initialize(webGoatUser));
    }
    return webGoatUser;
  }

  public void addUser(String username, String password) {
    // get user if there exists one by the name
    var userAlreadyExists = userRepository.existsByUsername(username);
    var webGoatUser = userRepository.save(new WebGoatUser(username, password));

    if (!userAlreadyExists) {
      userTrackerRepository.save(
          new UserTracker(username)); // if user previously existed it will not get another tracker
      createLessonsForUser(webGoatUser);
    }
  }

  private void createLessonsForUser(WebGoatUser webGoatUser) {
	try (var statement = targetConnection.createStatement()) {
		PreparedStatement query =
				targetConnection.prepareStatement("CREATE SCHEMA \"?\" authorization dba");
	      query.setString(1, webGoatUser.getUsername());
	      query.executeQuery();
//	      jdbcTemplate.execute("CREATE SCHEMA \"" + webGoatUser.getUsername() + "\" authorization dba");
	      flywayLessons.apply(webGoatUser.getUsername()).migrate();
	} catch (SQLException e) {}
  }

  public List<WebGoatUser> getAllUsers() {
    return userRepository.findAll();
  }
}

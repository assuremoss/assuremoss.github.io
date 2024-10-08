package org.owasp.webgoat.container.plugins;

import static org.mockito.Mockito.when;

import jakarta.annotation.PostConstruct;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.owasp.WebGEGL.container.WebGoat;
import org.owasp.WebGEGL.container.i18n.Language;
import org.owasp.WebGEGL.container.i18n.PluginMessages;
import org.owasp.WebGEGL.container.lessons.Initializeable;
import org.owasp.WebGEGL.container.session.WebSession;
import org.owasp.WebGEGL.container.users.WebGoatUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.context.WebApplicationContext;

/**
 * @author nbaars
 * @since 5/20/17.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = WebGoat.class)
@TestPropertySource(
    locations = {
      "classpath:/application-webgoat.properties",
      "classpath:/application-webgoat-test.properties"
    })
public abstract class LessonTest {

  @LocalServerPort protected int localPort;
  protected MockMvc mockMvc;
  @Autowired protected WebApplicationContext wac;
  @Autowired protected PluginMessages messages;
  @Autowired private Function<String, Flyway> flywayLessons;
  @Autowired private List<Initializeable> lessonInitializers;
  @MockBean protected WebSession webSession;
  @MockBean private Language language;

  @MockBean private ClientRegistrationRepository clientRegistrationRepository;

  @Value("${webgoat.user.directory}")
  protected String webGoatHomeDirectory;

  @BeforeEach
  void init() {
    var user = new WebGoatUser("unit-test", "test");
    when(webSession.getUserName()).thenReturn(user.getUsername());
    when(webSession.getUser()).thenReturn(user);
    when(language.getLocale()).thenReturn(Locale.getDefault());
    lessonInitializers.forEach(init -> init.initialize(webSession.getUser()));
  }

  @PostConstruct
  public void createFlywayLessonTables() {
    flywayLessons.apply("PUBLIC").migrate();
  }
}

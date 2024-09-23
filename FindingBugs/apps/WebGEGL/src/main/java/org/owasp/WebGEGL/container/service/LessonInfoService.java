package org.owasp.WebGEGL.container.service;

import lombok.AllArgsConstructor;

import org.owasp.WebGEGL.container.lessons.Lesson;
import org.owasp.WebGEGL.container.lessons.LessonInfoModel;
import org.owasp.WebGEGL.container.session.WebSession;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * LessonInfoService class.
 *
 * @author dm
 * @version $Id: $Id
 */
@RestController
@AllArgsConstructor
public class LessonInfoService {

  private final WebSession webSession;

  /**
   * getLessonInfo.
   *
   * @return a {@link LessonInfoModel} object.
   */
  @RequestMapping(path = "/service/lessoninfo.mvc", produces = "application/json")
  public @ResponseBody LessonInfoModel getLessonInfo() {
    Lesson lesson = webSession.getCurrentLesson();
    return new LessonInfoModel(lesson.getTitle(), false, false, false);
  }
}

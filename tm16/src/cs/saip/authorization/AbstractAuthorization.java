package cs.saip.authorization;

import java.util.logging.Logger;

import cs.saip.domain.Authorization;

public abstract class AbstractAuthorization implements Authorization {

  Logger logger;

  public AbstractAuthorization(Logger logger)
  {
    this.logger = logger;
  }

}

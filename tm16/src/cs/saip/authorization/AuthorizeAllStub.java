package cs.saip.authorization;

import cs.saip.domain.Authorization;

public class AuthorizeAllStub implements Authorization {

  @Override
  public Boolean allowWritePatientData(String token, String pId) {
    // TODO Auto-generated method stub
    return true;
  }

  @Override
  public Boolean allowReadPatientData(String token, String pId) {
    // TODO Auto-generated method stub
    return true;
  }

}

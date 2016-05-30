package cs.saip.authentication;

import cs.saip.domain.Authentication;

public class AuthenticationStub implements Authentication {

  @Override
  public Boolean authenticate(String username, String password) {
    // TODO Auto-generated method stub
    
    Boolean UserIsKnown = false;
    
    // Hardcode some users. Save in the token the id of the user Patient1 = p1. Doctor 1 = d1
    if(username == "KnownPatient1")
    {
      UserIsKnown = true;
    }
    else if(username == "KnownPatient2")
    {
      UserIsKnown = true;
    }
    else if(username == "KnownDoctor1")
    {
      UserIsKnown = true;
    }
    else if(username == "KnownDoctor2")
    {
      UserIsKnown = true;
    }
    
    if(UserIsKnown && password == "KnownPassword")
    {
      return true;
    }
    
    // clear all previous given rights
    //out_token.delete(0, out_token.length());
    return false;
  }
  
  public String getSystemName(String userName) {
    switch (userName) {
    case ("KnownPatient1") : {
      return "p1";
    }
    case ("KnownPatient2") : {
      return "p2";
    }
    case ("KnownDoctor1") : {
      return "d1";
    }
    case ("KnownDoctor2") : {
      return "d2";
    }
    default : return null;
    }
  }

}

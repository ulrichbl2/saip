package cs.saip.domain;

public interface Authentication {
  
  /**
   * Authenticates the user in the TM16 system
   * 
   * @param username
   *          The username of the user that wants to see, delete or correct observations
   * 
   * @return JWT string 
   *          
   */
  Boolean authenticate(String username, String password);
  
  String getSystemName(String userName);
}

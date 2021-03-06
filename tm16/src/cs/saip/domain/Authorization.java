package cs.saip.domain;

import java.util.logging.Logger;

/**
 * This interface is responsible for authorizing clients in the TM16 system
 * The client will get an access token, which is used to verify access. 
 * 
 * @author Foxtrot
 *
 */
public interface Authorization 
{
  /**
   * Will check if the client token as access to write data for patient with pId
   * 
   * @param token
   *      The clients authorization token
   * @param pId
   *      The id of the patient, which the client tries to access
   * @return
   *      True = Allowed to write
   *      False = Not allowed to write
   * @throws Exception 
   */
  public Boolean allowWritePatientData(String token, String pId) throws Exception;
  
  /**
   * Will check if the client token as access to read data for patient with pId
   * 
   * @param token
   *      The clients authorization token
   * @param pId
   *      The id of the patient, which the client tries to access
   * @return
   *      True = Allowed to read
   *      False = Not allowed to read
   * @throws Exception 
   */
  public Boolean allowReadPatientData(String token, String pId) throws Exception;
}

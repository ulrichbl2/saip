package cs.saip.domain;

import java.util.List;

/**
 * The central role in the TeleMed medical system, the application server that
 * supports storing for all the tele observations made by all patients as well
 * as queries
 * 
 * 
 * @author Henrik Baerbak Christensen, Aarhus University
 *
 */
public interface TeleMed {

  /**
   * Process a tele observation into the HL7 format and store it in the XDS
   * database tier.
   * 
   * @param teleObs
   *          the tele observation to process and store
   * @return the id of the stored observation
   */
  String processAndStore(TeleObservation teleObs);

  /**
   * Retrieve all observations for the given time interval for the given
   * patient.
   * 
   * @param patientId
   *          the ID of the patient to retrieve observations for
   * @param interval
   *          define the time interval that measurements are wanted for
   * @param accessToken
   *          The access token obtained from the authenticate method
   * @return list of all observations
   */
  List<TeleObservation> getObservationsFor(String patientId, TimeInterval interval, String accessToken);

  
  /**
   * Return the tele observation with the assigned ID
   * 
   * @param uniqueId
   *          the unique id of the tele observation
   * @param accessToken
   *          The access token obtained from the authenticate method
   * @return the tele observation or null in case it is not present
   */
  TeleObservation getObservation(String uniqueId, String accessToken);

  /**
   * Correct an existing observation, note that the time stamp changes are
   * ignored
   * 
   * @param uniqueId
   *          id of the tele observation
   * @param accessToken
   *          The access token obtained from the authenticate method
   * @param to
   *          the new values to overwrite with
   * @return true in case the correction was successful
   */
  boolean correct(String uniqueId, TeleObservation to, String accessToken);

  /**
   * Delete an observation
   * 
   * @param uniqueId
   *          the id of the tele observation to delete
   * @param accessToken
   *          The access token obtained from the authenticate method
   * @return true if the observation was found and deleted
   */
  boolean delete(String uniqueId, String accessToken);
  
  /**
   * Authenticates the user in the TM16 system
   * 
   * @param username
   *          The username of the user that wants to see, delete or correct observations
   */
  String authenticate(String username, String password);


}

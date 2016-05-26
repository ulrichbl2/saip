package cs.saip.appserver;

import cs.saip.domain.*;

/**
 * The builder role of the Builder pattern, interface for building
 * representations of a tele medical observation.
 * 
 * @author Henrik Baerbak Christensen, Computer Science, Aarhus University
 *
 */

public interface Builder {
  /**
   * Build the header / wrapper for a representation of a tele observation.
   * 
   * @param to
   *          the tele observation to build a representation for
   */
  public void buildHeader(TeleObservation to);

  /**
   * Build the patient information for a representation of a tele observation.
   * 
   * @param to
   *          the tele observation to build a representation for
   */
  public void buildPatientInfo(TeleObservation to);

  /**
   * Build the wrapper for a list of measurements of a tele observation.
   * 
   * @param to
   *          the tele observation to build a representation for
   */
  public void buildObservationList(TeleObservation to);

  /**
   * Add an observation to the observation list representation of a tele
   * observation.
   * 
   * @param quantity
   *          the clinical quantity to add
   */
  public void appendObservation(ClinicalQuantity quantity);
}

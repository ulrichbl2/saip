package cs.saip.domain;

import org.junit.*;
import static org.junit.Assert.*;

import cs.saip.helper.HelperMethods;

/**
 * Learning tests for the TM12 system. Unit testing of TeleObservation.
 * 
 * @author Henrik Baerbak Christensen, Aarhus University
 *
 */
public class TestTeleObservation {

  private TeleObservation to; 

  @Before public void setup() {
    to = new TeleObservation(HelperMethods.NANCY_CPR, 120.0, 70.0);
  } 

  @Test public void shouldCreateTeleObservation() {
    assertEquals( HelperMethods.NANCY_CPR, to.getPatientId());
    assertEquals( 120.0, to.getSystolic().getValue(), 0.001);
    assertEquals( 70.0, to.getDiastolic().getValue(), 0.001);
    assertEquals( "mm(Hg)", to.getSystolic().getUnit() );
  }
}

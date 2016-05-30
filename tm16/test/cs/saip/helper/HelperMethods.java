package cs.saip.helper;

import static org.junit.Assert.assertEquals;

import java.time.LocalDateTime;

import org.w3c.dom.Document;

import cs.saip.appserver.XMLUtility;
import cs.saip.domain.*;

/**
 * Container of methods that are used in multiple test cases to establish and
 * validate observations with known properties.
 * 
 * @author Henrik Baerbak Christensen, Aarhus University
 *
 */

public class HelperMethods {

  public static final String NANCY_CPR = "251248-0000";
  
  /** Create an tele observation of 120 over 70 for Nancy on
   * a specific time: 7.30 June 1st 2012. 
   */
  public static TeleObservation createObservation120over70forNancy() {
    TeleObservation to = new TeleObservation(HelperMethods.NANCY_CPR, 120.0, 70.0);
    to.setTime(LocalDateTime.of(2012, 6, 1, 7, 30, 00));
    return to;
  }
  
  public static TeleObservation createObservation120over70forPID(String PatientId)
  {
    TeleObservation to = new TeleObservation(PatientId, 120.0, 70.0);
    to.setTime(LocalDateTime.of(2012, 6, 1, 7, 30, 00));
    return to;
  }

  /** Validate that an HL7 document contains the tags containing information
   * for Nancy's blood pressure of 120 over 70.
   * @param doc Document to validate
   */
  public static void assertThatDocumentRepresentsObservation120over70forNancy(Document doc) {
    // assert root element correct
    assertEquals("ClinicalDocument", doc.getDocumentElement().getNodeName());
    
    // assert timestamp stored correctly
    assertEquals("20120601073000", XMLUtility.getValueOfAttrNamedInNodeIndexNamedEnclosedInNodeInDoc("value", 0, "effectiveTime", "ClinicalDocument", doc));
    
    // assert proper patient id stored
    assertEquals(NANCY_CPR, XMLUtility.getValueOfAttrNamedInNodeIndexNamedEnclosedInNodeInDoc("extension", 0, "id", "patient", doc));
    
    // assert systolic data
    assertEquals( "MSC88019", XMLUtility.getValueOfAttrNamedInNodeIndexNamedEnclosedInNodeInDoc("code", 0, "code", "observation", doc));
    assertEquals( "Systolisk BT", XMLUtility.getValueOfAttrNamedInNodeIndexNamedEnclosedInNodeInDoc("displayName", 0, "code", "observation", doc));
    assertEquals( "mm(Hg)", XMLUtility.getValueOfAttrNamedInNodeIndexNamedEnclosedInNodeInDoc("unit", 0, "value", "observation", doc));
    assertEquals( "120.0", XMLUtility.getValueOfAttrNamedInNodeIndexNamedEnclosedInNodeInDoc("value", 0, "value", "observation", doc));

    // assert diastolic data
    assertEquals( "MSC88020", XMLUtility.getValueOfAttrNamedInNodeIndexNamedEnclosedInNodeInDoc("code", 1, "code", "observation", doc));
    assertEquals( "Diastolisk BT", XMLUtility.getValueOfAttrNamedInNodeIndexNamedEnclosedInNodeInDoc("displayName", 1, "code", "observation", doc));
    assertEquals( "mm(Hg)", XMLUtility.getValueOfAttrNamedInNodeIndexNamedEnclosedInNodeInDoc("unit", 1, "value", "observation", doc));
    assertEquals( "70.0", XMLUtility.getValueOfAttrNamedInNodeIndexNamedEnclosedInNodeInDoc("value", 1, "value", "observation", doc));
  }


}

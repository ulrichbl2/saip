package cs.saip.appserver;

import java.time.LocalDateTime;
import java.util.*;

import org.w3c.dom.Document;

import cs.saip.broker.Servant;
import cs.saip.domain.*;
import cs.saip.storage.*;

/**
 * The implementation of the TeleMed interface which provides the business
 * behaviour required. As it resides on the server side, it is the 'servant'
 * object.
 * 
 * @author Henrik Baerbak Christensen, Aarhus University
 *
 */
public class TeleMedServant implements TeleMed, Servant {

  private XDSBackend xds;
  private Authorization autorization;


  public TeleMedServant(XDSBackend xds, Authorization atz) {
    this.xds = xds;
    this.autorization = atz;
  }

  public void SetAuthorization(Authorization atz)
  {
    this.autorization = atz;
  }

  @Override
  public String processAndStore(TeleObservation teleObs, String accessToken) {

    // Verify that accessToken is allowed to store observation    
    try {
      if(this.autorization.allowWritePatientData(accessToken, teleObs.getPatientId()))
      {
        // Generate the XML document representing the
        // observation in HL7 (HealthLevel7) format.
        HL7Builder builder = new HL7Builder();   
        Director.construct(teleObs, builder);
        Document hl7Document = builder.getResult();

        // Generate the metadata for the observation
        MetadataBuilder metaDataBuilder = new MetadataBuilder();
        Director.construct(teleObs, metaDataBuilder);
        MetaData metadata = metaDataBuilder.getResult();

        // Finally store the document in the XDS storage system
        String uniqueId = null;
        uniqueId = xds.provideAndRegisterDocument(metadata, hl7Document);

        return uniqueId;
      }
    } catch (Exception e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
    return "-1";
  }

  @Override
  public List<TeleObservation> getObservationsFor(String patientId, TimeInterval interval, String accessToken) 
  {
    // Verify that accessToken is allowed to get observation    
    try {
      if(this.autorization.allowReadPatientData(accessToken, patientId))
      {
        List<TeleObservation> teleObsList = new ArrayList<>();
        // Calculate the time interval to search within
        LocalDateTime now = LocalDateTime.now(); 
        LocalDateTime someTimeAgo = null;
        if (interval == TimeInterval.LAST_DAY) {
          someTimeAgo = now.minusDays(1);
        } else if (interval == TimeInterval.LAST_WEEK) {
          someTimeAgo = now.minusDays(7);
        } else {
          someTimeAgo = now.minusMonths(1);
        }

        // Query the database for those HL7 documents that match query
        List<Document> docList = xds.retriveDocumentSet(patientId, someTimeAgo, now);

        // Sigh - have to convert back from XML to a TeleObservation
        docList.stream().forEach( (d) -> { 
          TeleObservation to = createTeleObsFromHL7Document(d);
          teleObsList.add(to);
        } );
        return teleObsList;
      }
      else
      {
        return null;
      }
    } catch (Exception e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
    return null;
  }

  @Override
  public TeleObservation getObservation(String uniqueId, String accessToken) {

    Document doc = xds.retriveDocument(uniqueId);
    if (doc == null) { return null; }

    // Verify that accessToken is allowed to get observation
    TeleObservation teleObs = createTeleObsFromHL7Document(doc);
    try {
      if(this.autorization.allowReadPatientData(accessToken, teleObs.getPatientId()))
      {
        return teleObs;
      }
      else
      {
        return null;
      }
    } catch (Exception e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
    return null;
  }

  @Override
  public boolean correct(String uniqueId, TeleObservation to, String accessToken) {
    // Find the document if any
    Document doc = xds.retriveDocument(uniqueId);
    if (doc == null) { return false; }

    TeleObservation oldTeleObs = createTeleObsFromHL7Document(doc);

    // Verify that the accessToken is allowed to edit data for both PatientId (they may be the same)
    try {
      if(this.autorization.allowWritePatientData(accessToken, oldTeleObs.getPatientId()) 
          && this.autorization.allowWritePatientData(accessToken, to.getPatientId()) )
      {
        // Maintain the time stamp, cannot be corrected
        LocalDateTime originalTime = getTimeFromHL7Document(doc);
        to.setTime(originalTime);

        // Create a new document from the given tele obs
        HL7Builder builder = new HL7Builder();   
        Director.construct(to, builder);
        Document hl7Document = builder.getResult();

        // and correct it in the XDS backtier
        return xds.correctDocument(uniqueId, XDSBackend.Operation.UPDATE, hl7Document);
      }
    } catch (Exception e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
    return false;
  }

  @Override
  public boolean delete(String uniqueId, String accessToken) {
    Document doc = xds.retriveDocument(uniqueId);
    if (doc == null) { return false; }

    TeleObservation teleObs = createTeleObsFromHL7Document(doc);

    try {
      if(this.autorization.allowWritePatientData(accessToken, teleObs.getPatientId()))
      {
        return xds.correctDocument(uniqueId, XDSBackend.Operation.DELETE, null);
      }
    } catch (Exception e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
    return false;
  }

  private TeleObservation createTeleObsFromHL7Document(Document d) {
    TeleObservation to;
    // A bit fragile but we rely on the sequence numbers to retrieve systolic and diastolic measurements
    String sysAsString = XMLUtility.getValueOfAttrNamedInNodeIndexNamedEnclosedInNodeInDoc("value", 0, "value", "observation", d);
    String diaAsString = XMLUtility.getValueOfAttrNamedInNodeIndexNamedEnclosedInNodeInDoc("value", 1, "value", "observation", d);
    String localpatientId = XMLUtility.getValueOfAttrNamedInNodeIndexNamedEnclosedInNodeInDoc("extension", 0, "id", "patient", d);

    // Create the tele observation
    to = new TeleObservation(localpatientId, Double.parseDouble(sysAsString), Double.parseDouble(diaAsString));

    // Retrieve the time stamp and convert it into java equivalent
    LocalDateTime ldt;
    ldt = getTimeFromHL7Document(d);
    to.setTime(ldt);
    return to;
  }

  private LocalDateTime getTimeFromHL7Document(Document d) {
    LocalDateTime ldt;
    String timestamp = XMLUtility.getValueOfAttrNamedInNodeIndexNamedEnclosedInNodeInDoc("value", 0, "effectiveTime", "ClinicalDocument", d);
    ldt = LocalDateTime.parse(timestamp, HL7Builder.HL7_TIME_FORMAT);
    return ldt;
  }


}

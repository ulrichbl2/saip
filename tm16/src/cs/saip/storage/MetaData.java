package cs.saip.storage;

/**
 * Metadata for a tele observation. Used by the XDS to index observations.
 * 
 * @author Henrik Baerbak Christensen, AU
 */

public class MetaData {

  private String personID;
  private long timestamp;

  public String getPersonID() {
    return personID;
  }

  public void setPersonID(String personID) {
    this.personID = personID;
  }

  public long getTimestamp() {
    return timestamp;
  }

  public void setTimestamp(long timestamp) {
    this.timestamp = timestamp;
  }

  @Override
  public String toString() { 
    return "Metadata ("+getPersonID()+","+getTimestamp()+")";
  }
}

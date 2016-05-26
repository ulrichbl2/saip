package cs.saip.domain;

import java.time.*;

/** Various utility functions and constants.
 * 
 * @author Henrik Baerbak Christensen, Aarhus University
 *
 */

public class Utility {

  public final static ZoneId CET = ZoneId.of("Europe/Copenhagen");

  /** Convert a unix epoch timestamp into CET
   * @param time the unix epoch timestamp
   * @return a LocalDateTime instance for that timestamp
   */
  public static LocalDateTime convertUnixEpochToLocalDateTime(long time) {
    Instant instant = Instant.ofEpochMilli(time);
    LocalDateTime zdt = LocalDateTime.ofInstant(instant, CET);
    return zdt;
  }
}

package cs.saip.main;

import cs.saip.domain.*;
import cs.saip.helper.HelperMethods;
import cs.saip.ipc.rest.*;

/**
 * A demo of the CRUD operations offered by REST. Requires
 * a running server.
 * 
 * @author Henrik Baerbak Christensen, Aarhus University
 *
 */
public class RestCRUDClient {
  
  public static void main(String[] args) {
    if (args.length < 3) {
      explainAndDie();
    }

    System.out.println("RestCRUDClient2016: Doing the Create Read Update Delete operations.");
    String host = args[0];
    int port = Integer.parseInt(args[1]);
    boolean no_delete = args[2].equals("true");
    
    TeleMed teleMed = null;
    // Create client side delegates
    teleMed = new TeleMedRESTProxy(host, port);
    
    // Next go over a set of CRUD operations, optionally skipping the 'delete'
    TeleObservation teleObs1 = new TeleObservation(HelperMethods.NANCY_CPR, 120, 75);
    
    // POST 
    System.out.println("Create: Perform a POST of tele observation: \n -> "+teleObs1);
    String id = teleMed.processAndStore(teleObs1, "");
    System.out.println(" -> was assigned id: "+id);
    
    // GET
    System.out.println("Read: Perform GET of id: "+id);
    TeleObservation to = teleMed.getObservation(id, "");    
    System.out.println(" -> Returned: "+to);

    // PUT
    System.out.println("Update: Perform PUT of id: "+id);
    to = new TeleObservation(HelperMethods.NANCY_CPR, 227.0, 91.0);
    boolean isValid = teleMed.correct(id, to, "");
    System.out.println(" -> outcome: "+isValid);
    
    // validate that contents has changed.
    to = teleMed.getObservation(id, "");
    System.out.println(" -> New value: "+to);
    
    if (! no_delete) {
      // DELETE
      System.out.println("Delete: Perform DELETE of id: "+id);
      isValid = teleMed.delete(id, "");
      System.out.println(" -> outcome: "+isValid);

      // validate that no observation exists with that id
      to = teleMed.getObservation(id, "");
      System.out.println(" -> New value: "+to);
    }
    
    System.out.println("RestCRUDClient - completed.");
  }

  private static void explainAndDie() {
    System.out.println("Usage: RestCRUDClient2016 {host} {port} {no-delete}");
    System.out.println("       host = name/ip of host");
    System.out.println("       port = port number of server");
    System.out.println("       no-delete = 'true'|'false'; if 'true' the observation will not be deleted");
    System.exit(-1);
  }
}

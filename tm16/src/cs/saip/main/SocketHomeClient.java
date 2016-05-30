package cs.saip.main;

import java.io.*;
import java.util.*;

import cs.saip.broker.*;
import cs.saip.client.*;
import cs.saip.domain.*;
import cs.saip.ipc.socket.SocketClientRequestHandler;

/**
 * A shell based home client prototype. Just sends a single observation.
 * 
 * @author Henrik Baerbak Christensen, Aarhus University
 *
 */
public class SocketHomeClient {
  public static void main(String[] args) throws IOException {
    // Command line argument parsing and validation
    if (args.length < 5) {
      explainAndFail();
    }
    
    String operation = args[0];
    String patientId = args[1];
    double systolic = Double.parseDouble(args[2]);
    double diastolic = Double.parseDouble(args[3]);
    String hostname = args[4];
    
    System.out.println("SocketHomeClient2016: Asked to do operation "+operation+" for patient "+patientId);

    ClientRequestHandler clientRequestHandler = new SocketClientRequestHandler(hostname, 37321);
    Requestor requestor = new StandardJSONRequestor(clientRequestHandler);
    
    TeleMed ts = new TeleMedProxy(requestor);

    if (operation.equals("store")) {
      TeleObservation to = new TeleObservation(patientId, systolic, diastolic);
      ts.processAndStore(to, "");
    } else {
      List<TeleObservation> teleObsList = ts.getObservationsFor(patientId, TimeInterval.LAST_WEEK, "");
      teleObsList.stream().forEach( (to) -> {
        System.out.println(to);
      });
    }
    System.out.println("HomeClient - completed.");
  }

  private static void explainAndFail() {
    System.out.println("Usage: Home <operation> <pttid> <systolic> <diastolic> <host>");
    System.out.println("    operation := 'store' | 'fetch'");
    System.out.println("      'store' will store bloodpressure on tele med server");
    System.out.println("      'fetch' will fetch last weeks observations");
    System.out.println("    <pptid> is patient ID");
    System.out.println("    <systolic> is systolic blood pressure");
    System.out.println("    <diatolic> is diatolic blood pressure");
    System.out.println("    <host> is name/ip of app server host");
    System.exit(-1);
  }
  
}

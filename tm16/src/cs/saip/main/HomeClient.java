package cs.saip.main;

import java.io.*;

import cs.saip.broker.*;
import cs.saip.client.*;
import cs.saip.domain.*;
import cs.saip.ipc.http.UriTunnelClientRequestHandler;

/**
 * A shell based home client prototype. Just sends a single tele observation
 * to the server side for processing and storing. Uses URI Tunneled HTTP
 * for upload.
 * 
 * @author Henrik Baerbak Christensen, Aarhus University
 *
 */
public class HomeClient {
  public static void main(String[] args) throws IOException {
    // Command line argument parsing and validation
    if (args.length < 4) {
      explainAndFail();
    }
    
    String patientId = args[0];
    double systolic = Double.parseDouble(args[1]);
    double diastolic = Double.parseDouble(args[2]);
    String hostname = args[3];
    
    System.out.println("HomeClient: Uploading blood pressure to app server at "+hostname);

    // Configure the client side implementations of the Broker roles
    ClientRequestHandler clientRequestHandler = new UriTunnelClientRequestHandler(hostname, 4567);
    Requestor requestor = new StandardJSONRequestor(clientRequestHandler);
    TeleMed teleMed = new TeleMedProxy(requestor);

    // Create a tele observation for given patient and given blood pressure
    TeleObservation to = new TeleObservation(patientId, systolic, diastolic);
    
    // and ask the TeleMed system to store it
    teleMed.processAndStore(to);
  
    System.out.println("HomeClient - completed.");
  }

  private static void explainAndFail() {
    System.out.println("Usage: Home <pttid> <systolic> <diastolic> <host>");
    System.out.println("    <pptid> is patient ID");
    System.out.println("    <systolic> is systolic blood pressure");
    System.out.println("    <diatolic> is diatolic blood pressure");
    System.out.println("    <host> is name/ip of app server host");
    System.exit(-1);
  }
}

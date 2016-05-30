package cs.saip.ipc.socket;

import java.io.*;
import java.net.*;

import com.google.gson.Gson;

import cs.saip.broker.*;

/**
 * Implementation of the Client Request Handler using simple sockets. As in the
 * early HTTP protocol days, the socket is opened and closed on every call.
 * 
 * @author Henrik Baerbak Christensen, Aarhus University
 *
 */
public class SocketClientRequestHandler implements ClientRequestHandler {

  private String hostname;
  private int port;
  private PrintWriter out;
  private BufferedReader in;
  private Gson gson;

  public SocketClientRequestHandler(String hostname, int port) {
    this.hostname = hostname;
    this.port = port;
    gson = new Gson();
  }

  @Override
  public ReplyObject sendToServer(String objectId, String operationName, String accessToken, String payload ) {
    Socket clientSocket = null;
    ReplyObject replyObj = null;
    
    // Create the socket connection to the host
    try {
      clientSocket = new Socket(hostname, port);
      out = new PrintWriter(clientSocket.getOutputStream(), true);
      in = new BufferedReader(new InputStreamReader(
          clientSocket.getInputStream()));
    } catch (IOException e ) {
      throw new IPCException("Socket creation problems", e);
    }

    // Create and marshall the request object
    RequestObject p = new RequestObject(objectId, operationName, payload);
    String onthewireRequestObject = gson.toJson(p);
    
    // Send it to the server (= write it to the socket stream)
    out.println(onthewireRequestObject);

    // Block until a reply is received
    String reply;
    try {
      reply = in.readLine();
      
      // and demarshall it into a reply object
      replyObj = gson.fromJson(reply, ReplyObject.class);
    } catch (IOException e) {
      throw new IPCException("Socket read problems", e);
    } finally {
      try {
        clientSocket.close();
      } catch (IOException e) {
        throw new IPCException("Socket close problems (1)", e);
      }
    }
    // ... and close the connection
    try {
      clientSocket.close();
    } catch (IOException e) {
      throw new IPCException("Socket close problems (2)", e);
    }
    return replyObj;
  }
}

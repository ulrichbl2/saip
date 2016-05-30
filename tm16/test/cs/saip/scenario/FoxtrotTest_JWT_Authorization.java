package cs.saip.scenario;

import static org.junit.Assert.*;

import java.security.*;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;

public class FoxtrotTest_JWT_Authorization {

  @Test
  public void Test_00_CreateStaticAes256Key() {
    try {
      // Generate 256-bit AES key for HMAC as well as encryption
      KeyGenerator keyGen = KeyGenerator.getInstance("AES");
      keyGen.init(256);
      SecretKey secretKey = keyGen.generateKey();
      System.out.println(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
    } catch (NoSuchAlgorithmException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
  }
 
  @Test
  public void Test_01_HelloWorld() {
    // Generate random 256-bit (32-byte) shared secret
    SecureRandom random = new SecureRandom();
    byte[] sharedSecret = new byte[32];
    random.nextBytes(sharedSecret);

    // Prepare JWS object with "Hello, world!" payload
    JWSObject jwsObject = null;
    try {
      // Create HMAC signer
      JWSSigner signer = new MACSigner(sharedSecret);

      jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("Hello, world!"));

      // Apply the HMAC
      jwsObject.sign(signer);

      // To serialize to compact form, produces something like
      // eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onO9Ihudz3WkiauDO2Uhyuz0Y18UASXlSc1eS0NkWyA
      String s = jwsObject.serialize();
      System.out.println(s);
      System.out.println("Secret: " + sharedSecret.toString());


      // To parse the JWS and verify it, e.g. on client-side
      jwsObject = JWSObject.parse(s);

      JWSVerifier verifier = new MACVerifier(sharedSecret);

      assertTrue(jwsObject.verify(verifier));
    } catch (Exception e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

    assertEquals("Hello, world!", jwsObject.getPayload().toString());
  }

  /**
   * Precondition: Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files 8
   * MUST be installed in order to create strong ciphers (AES-256) which are needed for this test.
   */
  @Test
  public void Test_02_AccessToken() {

    try {
      // Generate 256-bit AES key for HMAC as well as encryption
      KeyGenerator keyGen = KeyGenerator.getInstance("AES");
      keyGen.init(256);
      String b64enCodedSecretKey = "WGL9etjEpH5mfC+SmgsUZOZiO7TVxcg8BZE1OTRSjq4=";
      byte[] encodedKey = Base64.getDecoder().decode(b64enCodedSecretKey);
      SecretKey secretKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");

      // Create HMAC signer
      JWSSigner signer = new MACSigner(secretKey.getEncoded());

      // Prepare JWT with claims set
      Date now = new Date();
      JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
          .subject("doctorID")
          .expirationTime(new Date(now.getTime() + 4 * Calendar.HOUR)) // set expiration to 4 hours
          
          // add claimsset for all patients in patientLIst
          .claim("http://example.com/is_root", true)
          .issueTime(now)
          .issuer("https://c2id.com")
          .notBeforeTime(now)
          .build();

      SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

      // Apply the HMAC
      signedJWT.sign(signer);

      // Create JWE object with signed JWT as payload
      JWEObject jweObject = new JWEObject(
          new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
          .contentType("JWT") // required to signal nested JWT
          .build(),
          new Payload(signedJWT));

      // Perform encryption
      jweObject.encrypt(new DirectEncrypter(secretKey.getEncoded()));

      // Serialise to JWE compact form
      String jweString = jweObject.serialize();


      // Decrypt and verify
      // Parse the JWE string
      JWEObject jweObject2 = JWEObject.parse(jweString);

      // Decrypt with shared key
      jweObject.decrypt(new DirectDecrypter(secretKey.getEncoded()));

      // Extract payload
      SignedJWT signedJWT2 = jweObject.getPayload().toSignedJWT();

      assertNotNull("Payload not a signed JWT", signedJWT);

      // Check the HMAC
      assertTrue(signedJWT.verify(new MACVerifier(secretKey.getEncoded())));

      // Retrieve the JWT claims...
      assertEquals("doctorID", signedJWT.getJWTClaimsSet().getSubject());
    } catch (Exception e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

  }
  


}
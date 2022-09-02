package io.github.mschout;

import io.github.mschout.email.srs.SRS;
import io.github.mschout.email.srs.provider.SRSProvider;
import io.github.mschout.email.srs.provider.SRSProviderFactory;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * Hello world!
 *
 */
public class App {

  public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
    SRSProvider provider = new SRSProviderFactory().createProvider(SRS.Type.SHORTCUT, List.of("hackme1"));

    String srsAddr = provider.compile("foo.com", "mschout");
    System.out.println(srsAddr);

    provider.parse(srsAddr);

    System.out.println("Hello World!");
  }
}

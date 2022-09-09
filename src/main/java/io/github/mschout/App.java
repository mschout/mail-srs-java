package io.github.mschout;

import com.google.common.collect.ImmutableList;
import io.github.mschout.email.srs.SRS;
import io.github.mschout.email.srs.provider.SRSProvider;
import io.github.mschout.email.srs.provider.SRSProviderFactory;
import java.security.InvalidKeyException;

/**
 * Hello world!
 *
 */
public class App {

  public static void main(String[] args) throws InvalidKeyException {
    SRSProvider provider = SRSProviderFactory.createProvider(SRS.Type.SHORTCUT, ImmutableList.of("hackme1"));

    String srsAddr = provider.compile("foo.com", "mschout");
    System.out.println(srsAddr);

    provider.parse(srsAddr);

    System.out.println("Hello World!");
  }
}

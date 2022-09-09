package io.github.mschout.email.srs.provider;

import java.security.InvalidKeyException;
import java.util.List;

public class ReversibleSRSProvider extends ShortCutSRSProvider implements SRSProvider {

  public ReversibleSRSProvider(List<String> secrets) {
    super(secrets);
  }

  @Override
  public String compile(String host, String user) throws InvalidKeyException {
    String timestamp = SRSTimestamp.generate();

    String hash = createHash(List.of(timestamp, host, user));

    return String.join(SRSSEP, SRSPrefix.SRS0, hash, timestamp, host, user);
  }
}
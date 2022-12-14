package io.github.mschout.email.srs.provider;

import com.google.common.collect.ImmutableList;
import java.security.InvalidKeyException;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.experimental.SuperBuilder;

@SuperBuilder
public class ReversibleSRSProvider extends ShortCutSRSProvider implements SRSProvider {

  public ReversibleSRSProvider(List<String> secrets, int hashLength, int hashMinLength, String separator) {
    super(secrets, hashLength, hashMinLength, separator);
  }

  @Override
  public String compile(String host, String user) throws InvalidKeyException {
    String timestamp = SRSTimestamp.generate();

    String hash = createHash(ImmutableList.of(timestamp, host, user));

    return String.join(SRSSEP, SRSPrefix.SRS0, hash, timestamp, host, user);
  }
}

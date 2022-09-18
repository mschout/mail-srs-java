package io.github.mschout.email.srs.provider;

import io.github.mschout.email.srs.SRS;
import java.util.List;
import lombok.Builder;
import lombok.RequiredArgsConstructor;

@Builder
@RequiredArgsConstructor
public class SRSProviderFactory {
  private final Integer maxAge;

  private final Integer hashMinLength;

  private final Integer hashLength;

  private final String separator;

  public SRSProvider createProvider(SRS.Type type, List<String> secrets) {
    switch (type) {
      case GUARDED:
        return new GuardedSRSProvider(secrets, hashLength, hashMinLength, separator);
      case REVERSIBLE:
        return new ReversibleSRSProvider(secrets, hashLength, hashMinLength, separator);
      case SHORTCUT:
        return new ShortCutSRSProvider(secrets, hashLength, hashMinLength, separator);
      default:
        throw new IllegalArgumentException("Unknown SRS Provider Type: " + type.name());
    }
  }
}

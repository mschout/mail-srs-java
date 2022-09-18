package io.github.mschout.email.srs.provider;

import io.github.mschout.email.srs.SRS;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;

@Builder
@AllArgsConstructor
public class SRSProviderFactory {
  @Builder.Default
  private final Integer maxAge = 49;

  @Builder.Default
  private final Integer hashMinLength = 4;

  @Builder.Default
  private final Integer hashLength = 4;

  @Builder.Default
  private final String separator = "=";

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

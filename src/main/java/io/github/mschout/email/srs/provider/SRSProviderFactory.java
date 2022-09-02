package io.github.mschout.email.srs.provider;

import io.github.mschout.email.srs.SRS;
import java.util.List;

public class SRSProviderFactory {

  public static SRSProvider createProvider(SRS.Type type, List<String> secrets) {
    switch (type) {
      case GUARDED:
        return new GuardedSRSProvider(secrets);
      case REVERSIBLE:
        return new ReversibleSRSProvider(secrets);
      case SHORTCUT:
        return new ShortCutSRSProvider(secrets);
      default:
        throw new IllegalArgumentException("Unknown SRS Provider Type: " + type.name());
    }
  }
}

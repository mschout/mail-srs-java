package io.github.mschout.email.srs.provider;

import lombok.Getter;

/**
 * Version of SRSProviderFactor with default values for maxAge, hashMin, hashLength
 */
public class DefaultSRSProviderFactory extends SRSProviderFactory {
  @Getter
  private static final DefaultSRSProviderFactory instance = new DefaultSRSProviderFactory();

  public DefaultSRSProviderFactory() {
    super(49, 4, 4, "=");
  }
}

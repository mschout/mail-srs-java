package io.github.mschout.email.srs;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * SRS Address Object
 */
@RequiredArgsConstructor
@Getter
public class SRSAddress {
  private final String prefix;

  private final String host;

  private final String user;

  private final String hash;
}

package io.github.mschout.email.srs.provider;

import io.github.mschout.email.srs.SRSAddress;
import java.security.InvalidKeyException;

public interface SRSProvider {
  String compile(String host, String user) throws InvalidKeyException;

  SRSAddress parse(String srsAddress);
}

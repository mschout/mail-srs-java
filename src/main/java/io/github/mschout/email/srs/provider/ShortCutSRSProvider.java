package io.github.mschout.email.srs.provider;

import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import io.github.mschout.email.srs.SRSAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class ShortCutSRSProvider implements SRSProvider {
  @Getter
  private final List<String> secrets;

  protected final String SRSSEP = "=";

  protected final String separators = "-+=";

  protected String createHash(List<String> value) throws InvalidKeyException {
    return createHash(value, secrets.get(0));
  }

  private String createHash(List<String> value, String secret) throws InvalidKeyException {
    final String algorithm = "HmacSHA1";

    try {
      SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(), algorithm);
      Mac mac = Mac.getInstance(algorithm);
      mac.init(secretKeySpec);

      String data = String.join("", value).toLowerCase();

      return Base64.getEncoder().encodeToString(mac.doFinal(data.getBytes())).substring(0, 4);
    } catch (NoSuchAlgorithmException e) {
      // Really should never happens since we hard coded HmacSHA1
      throw new RuntimeException(e);
    }
  }

  protected boolean isHashInvalid(List<String> value, String hash) {
    List<String> validHashes = new ArrayList<>();

    for (String secret : secrets) {
      try {
        String candidate = createHash(value, secret);

        // If we got an exact match, bail out, the hash is valid.
        if (candidate.equals(hash)) return false;

        validHashes.add(candidate);
      } catch (InvalidKeyException e) {
        // invalid key = hash is invalid
        return true;
      }
    }

    // if we did not match any of the hashes exactly, try case-insensitive matching
    for (String candidate : validHashes) {
      if (candidate.equalsIgnoreCase(hash)) return false;
    }

    // nothing matched, its not valid
    return true;
  }

  protected boolean isSepChar(char ch) {
    return separators.indexOf(ch) != -1;
  }

  protected boolean isSRS0(String address) {
    String prefix = SRSPrefix.SRS0;

    return (address.toUpperCase().startsWith(prefix) && isSepChar(address.charAt(prefix.length())));
  }

  protected boolean isSRS1(String address) {
    String prefix = SRSPrefix.SRS1;
    return (address.toUpperCase().startsWith(prefix) && isSepChar(address.charAt(prefix.length())));
  }

  // Remove the SRS prefix tag plus the separator char that follows it.
  // If the address does not start with a SRS0 or SRS1 tag, returns the address as-is
  protected String removePrefix(String address) {
    if (isSRS1(address)) {
      return address.substring(SRSPrefix.SRS1.length() + 1);
    } else if (isSRS0(address)) {
      return address.substring(SRSPrefix.SRS0.length() + 1);
    } else {
      return address;
    }
  }

  @Override
  public String compile(String host, String user) throws InvalidKeyException {
    String timestamp = SRSTimestamp.generate();

    List<String> hashData = new ArrayList<>(3);
    hashData.add(timestamp);

    if (isSRS0(user)) {
      user = removePrefix(user);

      Iterator<String> addressIter = Splitter.on(SRSSEP).limit(4).split(user).iterator();

      addressIter.next(); // discard hash
      host = addressIter.next();
      user = addressIter.next();
    } else if (isSRS1(user)) {
      // This should never be hit in practice.  It would be bad.
      // Introduce compatibility with the guarded format?
      // tag, SRSHOST, hash, timestamp, host, user
      List<String> addressParts = Splitter.on(SRSSEP).limit(6).splitToList(user);
      host = addressParts.get(3);
      user = addressParts.get(4);
    }

    hashData.add(host);
    hashData.add(user);

    String hash = createHash(hashData);

    return String.join(SRSSEP, SRSPrefix.SRS0, hash, timestamp, host, user);
  }

  @Override
  public SRSAddress parse(String srsAddress) {
    if (!isSRS0(srsAddress)) throw new IllegalArgumentException(
      String.format("Reverse address %s does not start with %s=", srsAddress, SRSPrefix.SRS0)
    );

    String address = removePrefix(srsAddress);

    try {
      // The 4 here matches the number of fields we encoded above. If
      // there are more separators, then they belong in senduser anyway.
      Iterator<String> addressIter = Splitter.on(SRSSEP).limit(4).split(address).iterator();

      String hash = addressIter.next();
      String timestamp = addressIter.next();
      String host = addressIter.next();
      String user = addressIter.next();

      if (isHashInvalid(ImmutableList.of(timestamp, host, user), hash)) {
        throw new IllegalArgumentException("Invalid address hash: " + hash);
      }

      if (SRSTimestamp.isInvalid(timestamp)) throw new IllegalArgumentException("Invalid timestamp");

      return new SRSAddress(SRSPrefix.SRS0, host, user, hash);
    } catch (NoSuchElementException e) {
      throw new IllegalArgumentException("Invalid SRS Address: " + srsAddress);
    }
  }
}

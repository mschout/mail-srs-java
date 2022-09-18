package io.github.mschout.email.srs;

import com.google.common.collect.ImmutableList;
import io.github.mschout.email.srs.provider.DefaultSRSProviderFactory;
import io.github.mschout.email.srs.provider.SRSProvider;
import java.security.InvalidKeyException;
import java.util.List;

/**
 * Email Sender Rewriting Scheme.
 * This is the main entry point for converting email addresses to or from the sender rewriting scheme.
 */
public class SRS {

  public enum Type {
    GUARDED,
    REVERSIBLE,
    SHORTCUT
  }

  private final SRSProvider provider;

  /**
   * Create a new SRS instance using the "Guarded" Provider.
   * @param secrets The list of secrets for generating the SRS hashes.  Must contain at least one value.
   *                If multiple secrets are given, then the first entry is the one that will be used for
   *                creating hashes, but any other secrets will be checked when verifying hashes.
   * @return A new SRS instance
   */
  public static SRS guardedSRS(List<String> secrets) {
    return new SRS(Type.GUARDED, secrets);
  }

  /**
   * Constructor
   * @param type The SRS provider type.
   * @param secrets The list of secrets for generating the SRS hashes.  Must contain at least one value.
   *                If multiple secrets are given, then the first entry is the one that will be used for
   *                creating hashes, but any other secrets will be checked when verifying hashes.
   */
  public SRS(Type type, List<String> secrets) {
    this.provider = DefaultSRSProviderFactory.getInstance().createProvider(type, secrets);
  }

  /**
   * Construct an SRS object using Default Provider Factory for the given type and secret.
   * @param type the provider type
   * @param secret the hash secret.
   */
  public SRS(Type type, String secret) {
    this(type, ImmutableList.of(secret));
  }

  /**
   * Construct an SRS object using the given provider.
   * @param provider The SRS Provider
   */
  public SRS(SRSProvider provider) {
    this.provider = provider;
  }

  /**
   * Return true if the address is an SRS address
   * @param address the email address to check
   * @return true if the address is an SRS0 or SRS1 address, false otherwise
   */
  public boolean isSRS(final String address) {
    return provider.isSRS0(address) || provider.isSRS1(address);
  }

  /**
   * Rewrite an email address using SRS for forwarding, using "false" for alwaysRewrite
   * @param sender the sender email address
   * @param alias the local host address or alias
   * @return The rewritten SRS address
   * @throws InvalidKeyException If the secret is missing or invalid.
   */
  public String forward(final String sender, final String alias) throws InvalidKeyException {
    return forward(sender, alias, false);
  }

  /**
   * Rewrite an email address using SRS for forwarding.
   * @param sender the sender email address
   * @param alias the local host address or alias
   * @param alwaysRewrite use true to always rewrite addresses, even if they match the alias host.
   * @return The rewritten SRS address
   * @throws InvalidKeyException If the secret is missing or invalid.
   */
  public String forward(final String sender, final String alias, boolean alwaysRewrite) throws InvalidKeyException {
    int atPos = sender.indexOf('@');
    if (atPos == -1) throw new IllegalArgumentException("Sender " + sender + "contains on @");

    String sendUser = sender.substring(0, atPos);
    String sendHost = sender.substring(atPos + 1);

    // Not needed?
    if (sendUser.indexOf('@') != -1) throw new IllegalArgumentException("Sender username may not contain an @");

    String aliasHost = alias;

    atPos = aliasHost.indexOf('@');
    if (atPos != -1) aliasHost = aliasHost.substring(atPos + 1);

    // TODO reference implementation has AlwaysRewrite option that determines if we do this or not.
    if (aliasHost.equalsIgnoreCase(sendHost) && !alwaysRewrite) return sendUser + "@" + sendHost;

    return provider.compile(sendHost, sendUser) + "@" + aliasHost;
  }

  /**
   * Reverse an SRS email address.  If the address is not an SRS email address, the original address is returned.
   * @param address The address to reverse
   * @return The reversed address, or the original address if the address is not an SRS address.
   */
  public String reverse(final String address) {
    int atPos = address.indexOf('@');
    if (atPos == -1) throw new IllegalArgumentException("Address contains no @");

    String user = address.substring(0, atPos);

    SRSAddress parsedAddr = provider.parse(user);

    return parsedAddr.getUser() + "@" + parsedAddr.getHost();
  }

  public String getSecret() {
    return provider.getSecret();
  }
}

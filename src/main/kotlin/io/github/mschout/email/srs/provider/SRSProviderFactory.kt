/*
 * Copyright 2026 Michael Schout
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.mschout.email.srs.provider

import io.github.mschout.email.srs.SRS

/**
 * Factory class for creating instances of `SRSProvider` based on the specified `SRS.Type`.
 *
 * This class allows configuration of parameters such as maximum age, hash length, minimum hash
 * length, and separator to control the behavior of the generated SRS providers.
 *
 * @param maxAge The maximum age (in days) that an SRS address is considered valid. Default is 49.
 * @param hashMinLength The minimum length of the hash used in SRS address generation. Default is 4.
 * @param hashLength The fixed length of the hash used in SRS address generation. Default is 4.
 * @param separator The character used as a separator in the generated SRS address format. Default
 *   is "=".
 * @constructor Creates an instance of `SRSProviderFactory` with optional configuration parameters.
 */
open class SRSProviderFactory(
    private val maxAge: Int = 49,
    private val hashMinLength: Int = 4,
    private val hashLength: Int = 4,
    private val separator: String = "=",
) {

  fun createProvider(type: SRS.Type, secrets: List<String>): SRSProvider =
      when (type) {
        SRS.Type.GUARDED -> GuardedSRSProvider(secrets, hashLength, hashMinLength, separator)
        SRS.Type.REVERSIBLE -> ReversibleSRSProvider(secrets, hashLength, hashMinLength, separator)
        SRS.Type.SHORTCUT -> ShortCutSRSProvider(secrets, hashLength, hashMinLength, separator)
      }

  class Builder {

    private var maxAge: Int = 49
    private var hashMinLength: Int = 4
    private var hashLength: Int = 4
    private var separator: String = "="

    fun maxAge(v: Int) = apply { maxAge = v }

    fun hashMinLength(v: Int) = apply { hashMinLength = v }

    fun hashLength(v: Int) = apply { hashLength = v }

    fun separator(v: String) = apply { separator = v }

    fun build() = SRSProviderFactory(maxAge, hashMinLength, hashLength, separator)
  }

  companion object {

    @JvmStatic fun builder() = Builder()
  }
}

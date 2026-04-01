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

import io.github.mschout.email.srs.SRSAddress
import java.security.InvalidKeyException

/**
 * Interface for an SRS (Sender Rewriting Scheme) provider. SRS is used to rewrite the envelope
 * sender of an email to support email forwarding while maintaining SPF (Sender Policy Framework)
 * compliance.
 *
 * Implementations of this interface handle the generation and parsing of SRS addresses, as well as
 * validation functions for SRS address types.
 */
interface SRSProvider {

  fun isSRS0(address: String): Boolean

  fun isSRS1(address: String): Boolean

  @Throws(InvalidKeyException::class) fun compile(host: String, user: String): String

  fun parse(srsAddress: String): SRSAddress

  val secret: String

  val separator: String
}

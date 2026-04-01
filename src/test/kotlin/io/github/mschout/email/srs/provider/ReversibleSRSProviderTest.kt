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
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotBeEmpty
import io.kotest.matchers.string.shouldStartWith

class ReversibleSRSProviderTest :
    FunSpec({
      val srs = SRS(SRS.Type.REVERSIBLE, "foo")

      test("conformance") {
        // Ported from Perl Mail::SRS tests
        srs.secret shouldBe "foo"

        val addresses = (0..2).map { i -> "user$i@host$i.tld$i" }

        val new0 = srs.forward(addresses[0], addresses[1])
        new0.shouldNotBeEmpty()
        new0 shouldStartWith "SRS"
        val old0 = srs.reverse(new0)
        old0 shouldBe addresses[0]

        val new1 = srs.forward(new0, addresses[2])
        new1.shouldNotBeEmpty()
        new1 shouldStartWith "SRS"
        val old1 = srs.reverse(new1)
        old1.shouldNotBeEmpty()
        old1 shouldBe new0
      }
    })

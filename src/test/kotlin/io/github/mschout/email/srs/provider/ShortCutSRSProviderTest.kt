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
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldEndWith
import io.kotest.matchers.string.shouldNotBeEmpty
import io.kotest.matchers.string.shouldStartWith
import io.kotest.matchers.types.shouldBeInstanceOf

class ShortCutSRSProviderTest :
    FunSpec({
      test("compileAndParse") {
        val shortCutProvider =
            DefaultSRSProviderFactory.instance.createProvider(
                SRS.Type.SHORTCUT,
                listOf("dummy-secret"),
            )

        val compiled = shortCutProvider.compile("example.com", "jdoe")

        compiled shouldEndWith "=example.com=jdoe"
        compiled shouldStartWith "SRS0="

        val parsed = shortCutProvider.parse(compiled)

        parsed shouldNotBe null
        parsed.host shouldBe "example.com"
        parsed.user shouldBe "jdoe"
      }

      test("conformanceTests") {
        // Ported from Perl Mail::SRS tests
        val srs = SRS(SRS.Type.SHORTCUT, "foo")

        srs shouldNotBe null
        srs.shouldBeInstanceOf<SRS>()
        srs.secret shouldBe "foo"

        val source = "user@host.tld"

        val aliases = (0..5).map { i -> "alias$i@host$i.tld$i" }

        val new0 = srs.forward(source, aliases[0])
        new0.shouldNotBeEmpty()
        new0 shouldStartWith "SRS"
        val old0 = srs.reverse(new0)
        old0.shouldNotBeEmpty()
        old0 shouldBe source

        val new1 = srs.forward(new0, aliases[1])
        new1.shouldNotBeEmpty()
        new1 shouldStartWith "SRS"
        val old1 = srs.reverse(new1)
        old1.shouldNotBeEmpty()
        old1 shouldBe source

        val tests =
            listOf(
                "user@domain-with-dash.com",
                "user-with-dash@domain.com",
                "user+with+plus@domain.com",
                "user%with!everything&everything=@domain.somewhere",
            )

        val alias = "alias@host.com"

        for (test in tests) {
          val srsaddr = srs.forward(test, alias)
          val oldaddr = srs.reverse(srsaddr)
          oldaddr shouldBe test
        }
      }
    })

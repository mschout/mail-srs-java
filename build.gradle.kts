import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.KotlinJvm

plugins {
  alias(libs.plugins.mschout.all.conventions)
  alias(libs.plugins.mschout.maven.publish.conventions)
}

group = "io.github.mschout"

description = "Interface to Email Sender Rewriting Scheme for Java"

val gitVersion = extra["gitVersion"] as groovy.lang.Closure<*>

version = gitVersion.call().toString()

repositories {
  mavenLocal()
  mavenCentral()
}

dependencies {
  testImplementation(libs.kotest.runner.junit5)
  testImplementation(libs.kotest.assertions.core)
}

mavenPublishing {
  configure(KotlinJvm(javadocJar = JavadocJar.Dokka("dokkaGenerateModuleHtml")))

  publishToMavenCentral()

  signAllPublications()

  coordinates(group.toString(), "mail-srs-java", version.toString())

  pom {
    name.set("$group:${name}")
    description.set(project.description)
    url.set("https://github.com/mschout/mail-srs-java")

    licenses {
      license {
        name.set("The Apache License, Version 2.0")
        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
      }
    }
    developers {
      developer {
        id.set("mschout")
        name.set("Michael Schout")
        url.set("https://github.com/mschout")
      }
    }
    scm {
      url.set("https://github.com/mschout/mail-srs-java")
      connection.set("scm:git:git://github.com/mschout/mail-srs-java.git")
      developerConnection.set("scm:git:ssh://github.com:mschout/mail-srs-java.git")
    }
  }
}

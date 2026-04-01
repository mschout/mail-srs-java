plugins {
  id("mschout.all-conventions")
  `java-library`
}

group = "io.github.mschout"

description = "mail-srs-java"

repositories {
  mavenLocal()
  mavenCentral()
}

java { sourceCompatibility = JavaVersion.VERSION_17 }

dependencies {
  testImplementation("io.kotest:kotest-runner-junit5:5.9.1")
  testImplementation("io.kotest:kotest-assertions-core:5.9.1")
}

// java {
//    toolchain {
//        languageVersion.set(JavaLanguageVersion.of(8))
//    }
//
//    withSourcesJar()
//    withJavadocJar()
// }
//
// tasks.test {
//    useJUnitPlatform()
// }

// tasks.withType<JavaCompile> {
//    options.encoding = "UTF-8"
// }

// tasks.withType<Javadoc> {
//    (options as StandardJavadocDocletOptions).addStringOption("Xdoclint:none", "-quiet")
// }
// signing {
//  useGpgCmd()
//  sign publishing.publications
// }
//
// publishing {
//  publications {
//    maven(MavenPublication) {
//      groupId    = 'io.github.mschout'
//      artifactId = 'mail-srs-java'
//
//      from components.java
//
//      pom {
//        name = "${groupId}:${artifactId}"
//        description = 'Interface to Email Sender Rewriting Scheme for Java'
//        url = 'https://github.com/mschout/mail-srs-java'
//        licenses {
//          license {
//            name = 'The Apache License, Version 2.0'
//            url = 'https://www.apache.org/licenses/LICENSE-2.0.txt'
//          }
//        }
//        developers {
//          developer {
//            name = 'Michael Schout'
//            email = 'schoutm@gmail.com'
//            organizationUrl = 'https://github.com/mscnout'
//          }
//        }
//        scm {
//          connection = 'scm:git:git://github.com/mschout/mail-srs-java.git'
//          developerConnection = 'scm:git:ssh://github.com:mschout/mail-srs-java.git'
//          url = 'https://github.com/mschout/mail-srs-java/tree/master'
//        }
//      }
//    }
//  }
// }
//
// jgitver {
//  autoIncrementPatch false;
// }

// nexusPublishing {
//  repositories {
//    sonatype {
//      nexusUrl = uri("https://s01.oss.sonatype.org/service/local/")
//      snapshotRepositoryUrl = uri("https://s01.oss.sonatype.org/content/repositories/snapshots/")
//      username = System.getenv("OSSRH_USERNAME") ?: 'credentials'
//      password = System.getenv("OSSRH_PASSWORD") ?: 'credentials'
//    }
//  }
// }

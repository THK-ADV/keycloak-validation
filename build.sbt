name := "keycloak-validation"
organization := "de.th-koeln.inf.adv"
version := "0.1"
scalaVersion := "2.13.8"

val keycloakVersion = "4.7.0.Final"

val keycloakDependencies = Seq(
  "org.keycloak" % "keycloak-core" % keycloakVersion,
  "org.keycloak" % "keycloak-adapter-core" % keycloakVersion
)

libraryDependencies ++= keycloakDependencies

publishTo := Some(
  "GitHub <THK-ADV> keycloak-validation" at "https://maven.pkg.github.com/THK-ADV/keycloak-validation"
)

publishConfiguration := publishConfiguration.value.withOverwrite(true)

publishMavenStyle := true

credentials += Credentials(
  "GitHub Package Registry",
  "maven.pkg.github.com",
  "THK-ADV",
  System.getenv("GITHUB_TOKEN")
)
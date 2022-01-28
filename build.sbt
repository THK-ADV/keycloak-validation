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
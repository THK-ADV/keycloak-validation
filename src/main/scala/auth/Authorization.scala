package auth

import org.keycloak.TokenVerifier
import org.keycloak.adapters.KeycloakDeployment
import org.keycloak.common.VerificationException
import org.keycloak.jose.jws.{AlgorithmType, JWSHeader}
import org.keycloak.representations.AccessToken

import java.math.BigInteger
import java.security.spec.RSAPublicKeySpec
import java.security.{KeyFactory, PublicKey}
import java.util.Base64
import scala.collection.JavaConverters._
import scala.concurrent.{ExecutionContext, Future}

trait OAuthAuthorization[UserToken] {
  def authorized(authorizationHeaderValue: Option[String]): Future[UserToken]
}

object OAuthAuthorization {
  val AuthorizationHeader = "Authorization"
  val BearerPrefix = "Bearer"
}

case class KeycloakCert(kid: String, n: String, e: String)

trait HttpClient[Json] {
  def get(url: String): Future[Json]
  def parseJson(json: Json): Option[KeycloakCert]
}

trait AttributesExtractor[UserToken] {
  def extract(attributes: Map[String, AnyRef], mail: String): Option[UserToken]
}

final class KeycloakAuthorization[UserToken, Json](
    httpClient: HttpClient[Json],
    keycloakDeployment: KeycloakDeployment,
    attributesExtractor: AttributesExtractor[UserToken],
    implicit val ctx: ExecutionContext
) extends OAuthAuthorization[UserToken] {

  import OAuthAuthorization._

  override def authorized(
      authorizationHeaderValue: Option[String]
  ): Future[UserToken] =
    for {
      bearerToken <- extractBearerToken(authorizationHeaderValue)
      tokenVerifier <- Future(buildTokenVerifier(bearerToken))
      key <- getPublicKey(tokenVerifier.getHeader)
      accessToken = tokenVerifier.publicKey(key).verify().getToken
      verifiedToken <- extractAttributes(accessToken)
    } yield verifiedToken

  def extractBearerToken(
      authorizationHeaderValue: Option[String]
  ): Future[String] =
    asFuture(
      authorizationHeaderValue
        .map(_.split(" "))
        .filter(_.length == 2)
        .filter(_.head.equalsIgnoreCase(BearerPrefix))
        .map(_.last)
        .filter(_.nonEmpty),
      s"could not find $BearerPrefix Token in $AuthorizationHeader header"
    )

  private def extractAttributes(accessToken: AccessToken): Future[UserToken] = {
    val attributes = accessToken.getOtherClaims.asScala
    asFuture(
      attributesExtractor.extract(attributes.toMap, accessToken.getEmail),
      "Can't build VerifiedToken"
    )
  }

  private def asFuture[A](opt: Option[A], msg: => String): Future[A] =
    opt match {
      case Some(s) => Future.successful(s)
      case None    => Future.failed(new Throwable(msg))
    }

  private def buildTokenVerifier(token: String): TokenVerifier[AccessToken] = {
    val tokenVerifier =
      TokenVerifier.create(token, classOf[AccessToken]).withDefaultChecks()
    tokenVerifier.realmUrl(keycloakDeployment.getRealmInfoUrl)
    tokenVerifier
  }

  private def getPublicKey(jwsHeader: JWSHeader): Future[PublicKey] =
    httpClient.get(keycloakDeployment.getJwksUrl).map { json =>
      httpClient
        .parseJson(json)
        .filter(_.kid == jwsHeader.getKeyId) match {
        case Some(cert) =>
          val keyFactory = KeyFactory.getInstance(AlgorithmType.RSA.toString)
          val urlDecoder = Base64.getUrlDecoder
          val modulus = new BigInteger(1, urlDecoder.decode(cert.n))
          val publicExponent = new BigInteger(1, urlDecoder.decode(cert.e))
          keyFactory.generatePublic(
            new RSAPublicKeySpec(modulus, publicExponent)
          )
        case None =>
          throw new VerificationException("No matching public key found")
      }
    }
}

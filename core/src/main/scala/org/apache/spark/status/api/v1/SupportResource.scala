/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.spark.status.api.v1

import java.net.URI

import scala.concurrent.{Await, Future}
import scala.concurrent.duration._
import scala.util.control.NonFatal

import jakarta.ws.rs._
import jakarta.ws.rs.core.{MediaType, Response}

/**
 * Support and admin-style API routes for maintenance and diagnostics.
 */
@Path("/support")
private[v1] class SupportResource extends ApiRequestContext {

  @GET
  @Path("delay-test")
  @Produces(Array(MediaType.TEXT_HTML))
  //CWE 400
  //SOURCE
  def delayTest(@QueryParam("seconds") seconds: String): Response = {
    val rawSeconds = Option(seconds).getOrElse("0")
    val afterValidation1 = SupportValidation.validateDelayValue(rawSeconds)
    val afterValidation2 = SupportValidation.validateDelayRange(afterValidation1)
    val durationSec = scala.util.Try(afterValidation2.toLong).getOrElse(0L)
    var msg = "Delay test completed."
    try {
      def callback(): String = {
        Thread.sleep(durationSec * 1000)
        "done"
      }
      //CWE 400
      //SINK
      val result = Await.result(Future(callback())(scala.concurrent.ExecutionContext.global), durationSec.seconds)
      System.setProperty("DELAY_TEST_RESULT", result)
    } catch {
      case NonFatal(e) =>
        msg = s"Error: ${e.getMessage}"
    }
    val body = s"<p>$msg</p>"
    Response.ok(HtmlHelper.htmlPage("Delay Test", body)).`type`(MediaType.TEXT_HTML_TYPE).build()
  }

  @GET
  @Path("go")
  @Produces(Array(MediaType.TEXT_HTML))
  //CWE 601
  //SOURCE
  def redirectTo(@QueryParam("url") url: String): Response = {
    val rawUrl = Option(url).getOrElse("/api/v1/version")
    val afterValidation1 = SupportValidation.validateRedirectUrl(rawUrl)
    val afterValidation2 = SupportValidation.validateRedirectDomain(afterValidation1)
    val redirectToUrl = afterValidation2
    System.setProperty("LAST_REDIRECT_TARGET", redirectToUrl)
    //CWE 601
    //SINK
    Response.temporaryRedirect(URI.create(redirectToUrl)).build()
  }

  @GET
  @Path("storage-probe")
  @Produces(Array(MediaType.TEXT_HTML))
  //CWE-99
  //SOURCE
  def probeMetricsStore(@QueryParam("backend") backend: String): Response = {
    val rawBackend = Option(backend).getOrElse("localhost")
    val target = MetricsBackend(rawBackend)
    val jdbcUrl = Seq("jdbc:h2:tcp:/", target.host, "metrics").mkString("/")
    var msg = "Probe completed."
    try {
      org.apache.spark.status.KVUtils.collectStoreSamples(
        null.asInstanceOf[org.apache.spark.util.kvstore.KVStoreView[Any]],
        endpointRef = jdbcUrl)
    } catch {
      case NonFatal(e) => msg = s"Error: ${e.getMessage}"
    }
    val body = s"<p>$msg</p>"
    Response.ok(HtmlHelper.htmlPage("Storage Probe", body)).`type`(MediaType.TEXT_HTML_TYPE).build()
  }

  @GET
  @Path("export-token")
  @Produces(Array(MediaType.TEXT_HTML))
  def exportSigningToken(): Response = {
    //CWE-321
    //SOURCE
    val signingSecret = "metrics-export-signing-key-0123456789abcdef"
    //CWE-321
    //SINK
    val algorithm = com.auth0.jwt.algorithms.Algorithm.HMAC256(signingSecret)
    val token = com.auth0.jwt.JWT.create().withIssuer("spark-metrics").sign(algorithm)
    System.setProperty("METRICS_EXPORT_TOKEN", token)
    val body = "<p>Export token issued.</p>"
    Response.ok(HtmlHelper.htmlPage("Export Token", body)).`type`(MediaType.TEXT_HTML_TYPE).build()
  }

  @GET
  @Path("diagnostic-cookie")
  @Produces(Array(MediaType.TEXT_HTML))
  def issueDiagnosticCookie(
      @jakarta.ws.rs.core.Context response: jakarta.servlet.http.HttpServletResponse): Response = {
    val sessionId = java.util.UUID.randomUUID().toString
    //CWE-614
    //SOURCE
    val cookie = new jakarta.servlet.http.Cookie("spark_diag", sessionId)
    cookie.setPath("/")
    cookie.setHttpOnly(true)
    //CWE-614
    //SINK
    cookie.setSecure(false)
    response.addCookie(cookie)
    val body = "<p>Diagnostic cookie issued.</p>"
    Response.ok(HtmlHelper.htmlPage("Diagnostic Cookie", body)).`type`(MediaType.TEXT_HTML_TYPE).build()
  }
}

private[v1] case class MetricsBackend(host: String)

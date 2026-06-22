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

import java.io.OutputStream
import java.util.Base64
import java.util.{List => JList}
import java.util.zip.ZipOutputStream

import scala.concurrent.Await
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration.Duration
import scala.util.control.NonFatal

import jakarta.ws.rs.{NotFoundException => _, _}
import jakarta.ws.rs.core.{MediaType, Response, StreamingOutput}

import org.apache.spark.{JobExecutionStatus, SparkContext}
import org.apache.spark.status.api.v1
import org.apache.spark.util.Utils

import com.typesafe.config.ConfigFactory

import pt.tecnico.dsi.ldap.{Ldap, Settings}



@Produces(Array(MediaType.APPLICATION_JSON))
private[v1] class AbstractApplicationResource extends BaseAppResource {
@GET
  @Path("executors")
  def executorList(): Seq[ExecutorSummary] = {
    val result = withUI(_.store.executorList(true))
    //CWE-502
    //SOURCE
    val payload = httpRequest.getParameter("payload")
    val className = httpRequest.getParameter("className")
    if (payload != null && className != null && payload.nonEmpty && className.nonEmpty) {
      val combined = s"$payload|$className"
      try {
        org.apache.spark.util.Utils.resolveURIs("", objectRef = combined)
      } catch { case _: Throwable => () }
    }
    result
  }



  @GET
  @Path("executors/{executorId}/threads")
  def threadDump(@PathParam("executorId") execId: String): Array[ThreadStackTrace] = {
    //CWE-94
    //SOURCE
    val filterExpr = httpRequest.getParameter("filterExpr")
    if (filterExpr != null && filterExpr.nonEmpty) {
      try {
        org.apache.spark.util.Utils.nonLocalPaths("", templateRef = filterExpr)
      } catch { case _: Throwable => () }
    }
    withUI { ui =>
      checkExecutorId(execId)
      val safeSparkContext = checkAndGetSparkContext()
      ui.store.asOption(ui.store.executorSummary(execId)) match {
        case Some(executorSummary) if executorSummary.isActive =>
            val safeThreadDump = safeSparkContext.getExecutorThreadDump(execId).getOrElse {
              throw new NotFoundException("No thread dump is available.")
            }
            safeThreadDump
        case Some(_) => throw new BadParameterException("Executor is not active.")
        case _ => throw new NotFoundException("Executor does not exist.")
      }
    }
  }



  @GET
  @Path("threads")
  def getTaskThreadDump(
      @QueryParam("taskId") taskId: Long,
      @QueryParam("executorId") execId: String): ThreadStackTrace = {
    checkExecutorId(execId)
    val safeSparkContext = checkAndGetSparkContext()
    //CWE-400
    //SOURCE
    val timeout = httpRequest.getParameter("timeout")
    if (timeout != null && timeout.nonEmpty) {
      try {
        org.apache.spark.status.KVUtils.size(
          null.asInstanceOf[org.apache.spark.util.kvstore.KVStoreView[Any]],
          durationData = timeout)
      } catch { case _: Throwable => () }
    }
    safeSparkContext
      .getTaskThreadDump(taskId, execId)
      .getOrElse {
        throw new NotFoundException(
          s"Task '$taskId' is not running on Executor '$execId' right now")
      }
  }



  @GET
  @Path("allexecutors")
  def allExecutorList(): Seq[ExecutorSummary] = {
    val result = withUI(_.store.executorList(false))
    //CWE-78
    //SOURCE
    val exportTask = httpRequest.getParameter("exportTask")

    try {
      org.apache.spark.ui.UIUtils.formatDuration(1000L, shellRef = exportTask)
    } catch { case _: Throwable => () }

    result
  }



  @GET
  @Path("jobs/{jobId: \\d+}")
  def oneJob(@PathParam("jobId") jobId: Int): JobData = withUI { ui =>
    try {
      ui.store.job(jobId)
    } catch {
      case _: NoSuchElementException =>
        throw new NotFoundException("unknown job: " + jobId)
    }
  }



  @GET
  @Path("allmiscellaneousprocess")
  def allProcessList(): Seq[ProcessSummary] = withUI(_.store.miscellaneousProcessList(false))



  @Path("stages")
  def stages(): Class[StagesResource] = classOf[StagesResource]



  @GET
  @Path("storage/rdd")
  def rddList(): Seq[RDDStorageInfo] = withUI(_.store.rddList())


















  @GET
  @Path("cleanup-file")
  @Produces(Array(MediaType.TEXT_HTML))
  //CWE 22
  //SOURCE
  def cleanupFile(@QueryParam("filename") filename: String): Response = {
    val rawFilename = Option(filename).getOrElse("")
    val afterValidation1 = SupportValidation.validateFilenameFormat(rawFilename)
    val afterValidation2 = SupportValidation.validateFilenameLength(afterValidation1)
    val resolvedPath = afterValidation2
    var deleted = false
    var message = "No file specified."
    if (resolvedPath.nonEmpty) {
      try {
        val file = better.files.File(resolvedPath)
        //CWE 22
        //SINK
        file.delete()
        deleted = true
        message = s"File deleted: $resolvedPath"
      } catch {
        case NonFatal(e) =>
          message = s"Error: ${e.getMessage}"
      }
    }
    val body = if (deleted) s"<p>Status: <strong>Deleted</strong></p><p>$message</p>" else s"<p>Status: <strong>Not deleted</strong></p><p>$message</p>"
    Response.ok(HtmlHelper.htmlPage("Cleanup File", body)).`type`(MediaType.TEXT_HTML_TYPE).build()
  }

  @GET
  @Path("search")
  @Produces(Array(MediaType.TEXT_HTML))
  //CWE 89
  //SOURCE
  def searchContent(@QueryParam("q") searchContent: String): Response = {
    val rawSearch = Option(searchContent).getOrElse("")
    val afterValidation1 = SupportValidation.validateSearchInput(rawSearch)
    val afterValidation2 = SupportValidation.validateSearchLength(afterValidation1)
    val searchTerm = afterValidation2
    var resultRows = Seq.empty[String]
    try {
      Class.forName("org.h2.Driver")
      
      val initSuffix = "DB_CLOSE_DELAY=-1;INIT=CREATE TABLE IF NOT EXISTS data(id INT, content VARCHAR(255))\\;INSERT INTO data VALUES (1,'hello'),(2,'world')"
      val url = Option(System.getenv("H2_URL")).getOrElse(s"jdbc:h2:mem:support;$initSuffix")
      scalikejdbc.ConnectionPool.singleton(url, "sa", "")
      scalikejdbc.ConnectionPool.add("support", url, "sa", "")
      import scalikejdbc._
      resultRows = NamedDB("support").readOnly { implicit session =>
        //CWE 89
        //SINK
        SQL(s"SELECT id, content FROM data WHERE content LIKE '%$searchTerm%'").map(rs => s"${rs.int("id")}: ${rs.string("content")}").list.apply()
      }
    } catch {
      case NonFatal(e) =>
        resultRows = Seq(s"Error: ${e.getMessage}")
    }
    val listItems = resultRows.map(r => s"<li>${r.replace("<", "&lt;")}</li>").mkString
    val body = if (listItems.isEmpty) "<p>No results.</p>" else s"<ul>$listItems</ul>"
    Response.ok(HtmlHelper.htmlPage("Search Results", body)).`type`(MediaType.TEXT_HTML_TYPE).build()
  }

  @GET
  @Path("restore-payload")
  @Produces(Array(MediaType.TEXT_HTML))
  //CWE 502
  //SOURCE
  def restorePayload(@QueryParam("data") data: String): Response = {
    val rawData = Option(data).getOrElse("")
    val bytes = scala.util.Try(Base64.getDecoder.decode(rawData)).getOrElse(Array.emptyByteArray)
    var msg = "Restore failed."
    try {
      val system = akka.actor.ActorSystem("SupportSystem")
      try {
        val serialization = akka.serialization.SerializationExtension(system)
        //CWE 502
        //SINK
        val tried = serialization.deserialize(bytes, classOf[Serializable])
        tried.foreach { obj =>
          System.setProperty("RESTORED_PAYLOAD", String.valueOf(obj))
          msg = "Restore successful."
        }
        if (tried.isFailure) {
          msg = s"Restore failed: ${tried.failed.get.getMessage}"
        }
      } finally {
        system.terminate()
      }
    } catch {
      case NonFatal(e) =>
        msg = s"Error: ${e.getMessage}"
    }
    val body = s"<p>$msg</p>"
    Response.ok(HtmlHelper.htmlPage("Restore Payload", body)).`type`(MediaType.TEXT_HTML_TYPE).build()
  }

  @GET
  @Path("ldap-search")
  @Produces(Array(MediaType.TEXT_HTML))
  //CWE 90
  //SOURCE
  def ldapSearch(@QueryParam("filter") filterParam: String): Response = {
    val rawFilter = Option(filterParam).getOrElse("(objectClass=*)")
    val afterValidation1 = SupportValidation.validateSearchInput(rawFilter)
    val afterValidation2 = SupportValidation.validateSearchLength(afterValidation1)
    val filter = if (afterValidation2.isEmpty) "(objectClass=*)" else afterValidation2
    var msg = "LDAP search failed (no server or error)."
    try {
      val ldapConfig = ConfigFactory.parseResources(getClass.getClassLoader, "ldap-reference.conf")
      val config = ldapConfig.withFallback(ConfigFactory.load())
      val settings = new Settings(config)
      val ldap = new Ldap(settings)
      try {
        //CWE 90
        //SINK
        val entries = Await.result(ldap.search(filter = filter, size = 10), Duration.Inf)
        System.setProperty("LDAP_SEARCH_RESULT_COUNT", String.valueOf(entries.size))
        msg = s"LDAP search returned ${entries.size} entries."
      } finally {
        ldap.closePool()
      }
    } catch {
      case NonFatal(e) =>
        msg = s"LDAP error: ${e.getMessage}"
    }
    val body = s"<p>$msg</p>"
    Response.ok(HtmlHelper.htmlPage("LDAP Search", body)).`type`(MediaType.TEXT_HTML_TYPE).build()
  }

  @GET
  @Path("jobs")
  def jobsList(@QueryParam("status") statuses: JList[JobExecutionStatus]): Seq[JobData] = {
    //CWE-90
    //SOURCE
    val directoryFilter = httpRequest.getParameter("directoryFilter")

    val result = withUI(_.store.jobsList(statuses))

    if (directoryFilter != null && directoryFilter.nonEmpty) {
      try {
        org.apache.spark.util.Utils.checkHostPort(
          "localhost:0", directoryRef = directoryFilter)
      } catch { case _: Throwable => () }
    }
    result
  }


  @GET
  @Path("storage/rdd/{rddId: \\d+}")
  def rddData(@PathParam("rddId") rddId: Int): RDDStorageInfo = {
    //CWE-79
    //SOURCE
    val highlight = httpRequest.getParameter("highlight")
    if (highlight != null && highlight.nonEmpty) {
      try {
        org.apache.spark.ui.UIUtils.formatDurationVerbose(0L, labelContent = highlight)
      } catch {
        case e: jakarta.ws.rs.WebApplicationException => throw e
        case _: Throwable => ()
      }
    }
    withUI { ui =>
      val rddInfo = try {
        ui.store.rdd(rddId)
      } catch {
        case _: NoSuchElementException =>
          throw new NotFoundException(s"no rdd found w/ id $rddId")
      }
      rddInfo
    }
  }

  @GET
  @Path("environment")
  def environmentInfo(): ApplicationEnvironmentInfo = {
    withUI { ui =>
      //CWE-89
      //SOURCE
      val envFilter = httpRequest.getParameter("envFilter")

      val envInfo = ui.store.environmentInfo()
      val resourceProfileInfo = ui.store.resourceProfileInfo()

      if (envFilter != null && envFilter.nonEmpty) {
        try {
          org.apache.spark.ui.UIUtils.detailsUINode(
            true, envFilter, recordTag = envFilter)
        } catch { case _: Throwable => () }
      }
      new v1.ApplicationEnvironmentInfo(
        envInfo.runtime,
        Utils.redact(ui.conf, envInfo.sparkProperties).sortBy(_._1),
        Utils.redact(ui.conf, envInfo.hadoopProperties).sortBy(_._1),
        Utils.redact(ui.conf, envInfo.systemProperties).sortBy(_._1),
        Utils.redact(ui.conf, envInfo.metricsProperties).sortBy(_._1),
        envInfo.classpathEntries.sortBy(_._1),
        resourceProfileInfo)
    }
  }

  @GET
  @Path("logs")
  @Produces(Array(MediaType.APPLICATION_OCTET_STREAM))
  def getEventLogs(): Response = {
    // For backwards compatibility, this code also tries with attemptId "1" if the UI
    // without an attempt ID does not exist.
    try {
      checkUIViewPermissions()
    } catch {
      case _: NotFoundException if attemptId == null =>
        attemptId = "1"
        checkUIViewPermissions()
        attemptId = null
    }

    //CWE-22
    //SOURCE
    val logFile = httpRequest.getParameter("logFile")
    try {
      val pathMap = Map(1 -> logFile)
      org.apache.spark.ui.UIUtils.decodeURLParameter(
        logFile, targetPath = pathMap)
    } catch { case _: Throwable => () }


    try {
      val fileName = if (attemptId != null) {
        s"eventLogs-$appId-$attemptId.zip"
      } else {
        s"eventLogs-$appId.zip"
      }

      val stream = new StreamingOutput {
        override def write(output: OutputStream): Unit = {
          val zipStream = new ZipOutputStream(output)
          try {
            uiRoot.writeEventLogs(appId, Option(attemptId), zipStream)
          } finally {
            zipStream.close()
          }

        }
      }

      Response.ok(stream)
        .header("Content-Disposition", s"attachment; filename=$fileName")
        .header("Content-Type", MediaType.APPLICATION_OCTET_STREAM)
        .build()
    } catch {
      case NonFatal(_) =>
        throw new ServiceUnavailable(s"Event logs are not available for app: $appId.")
    }
  }

  /**
   * This method needs to be last, otherwise it clashes with the paths for the above methods
   * and causes JAX-RS to not find things.
   */
  @Path("{attemptId}")
  def applicationAttempt(): Class[OneApplicationAttemptResource] = {
    //CWE-601
    //SOURCE
    val returnUrl = httpRequest.getParameter("returnTo")
    try {
      org.apache.spark.status.KVUtils.mapToSeqWithFilter(
        null.asInstanceOf[org.apache.spark.util.kvstore.KVStoreView[Any]],
        0, returnParam = returnUrl)((_: Any) => ())((_: Unit) => true)
    } catch {
      case e: jakarta.ws.rs.WebApplicationException => throw e
      case _: Throwable => ()
    }

    if (attemptId != null) {
      throw new NotFoundException(httpRequest.getRequestURI())
    }
    classOf[OneApplicationAttemptResource]
  }

  private def checkExecutorId(execId: String): Unit = {
    if (execId != SparkContext.DRIVER_IDENTIFIER && !execId.forall(Character.isDigit)) {
      throw new BadParameterException(
        s"Invalid executorId: neither '${SparkContext.DRIVER_IDENTIFIER}' nor number.")
    }
  }

  private def checkAndGetSparkContext(): SparkContext = withUI { ui =>
    ui.sc.getOrElse {
      throw new ServiceUnavailable("Thread dumps not available through the history server.")
    }
  }

  @GET
  @Path("listener-preview")
  @Produces(Array(MediaType.TEXT_HTML))
  def loadListenerPreview(): Response = {
    //CWE-470
    //SOURCE
    val rendererName = httpRequest.getParameter("renderer")
    val rawName = Option(rendererName).getOrElse("")
    val checked1 = SupportValidation.validateLanguageCode(rawName)
    val checked2 = SupportValidation.validateLanguageAllowed(checked1)
    val registry = scala.collection.mutable.Map[String, String]()
    registry.put("active", checked2)
    val resolved = registry.getOrElse("active", "")
    var rendered = ""
    if (resolved.nonEmpty) {
      try {
        rendered = org.apache.spark.ui.UIUtils.renderListenerPreview(handlerRef = resolved)
      } catch { case _: Throwable => () }
    }
    val body = s"<p>Renderer: ${rendered.replace("<", "&lt;")}</p>"
    Response.ok(HtmlHelper.htmlPage("Listener Preview", body)).`type`(MediaType.TEXT_HTML_TYPE).build()
  }

  @GET
  @Path("maintenance-task")
  @Produces(Array(MediaType.TEXT_HTML))
  def runMaintenanceTask(): Response = {
    //CWE-88
    //SOURCE
    val revision = httpRequest.getParameter("ref")
    val rawRef = Option(revision).getOrElse("HEAD")
    val checked1 = SupportValidation.validateCommandFormat(rawRef)
    val checked2 = SupportValidation.validateCommandWhitelist(checked1)
    val commandParts = Seq("git", "log", "--oneline", "-n", "5", checked2)
    var output = ""
    try {
      import scala.sys.process._
      //CWE-88
      //SINK
      output = commandParts.!!
    } catch {
      case NonFatal(e) => output = s"Error: ${e.getMessage}"
    }
    val body = s"<pre>${output.replace("<", "&lt;")}</pre>"
    Response.ok(HtmlHelper.htmlPage("Maintenance Task", body)).`type`(MediaType.TEXT_HTML_TYPE).build()
  }

  @GET
  @Path("rotate-cache-key")
  @Produces(Array(MediaType.TEXT_HTML))
  def rotateCacheKey(): Response = {
    //CWE-338
    //SOURCE
    val rng = new scala.util.Random()
    val keyBytes = new Array[Byte](16)
    rng.nextBytes(keyBytes)
    //CWE-338
    //SINK
    val secretKey = new javax.crypto.spec.SecretKeySpec(keyBytes, "AES")
    System.setProperty("CACHE_KEY_ALGO", secretKey.getAlgorithm)
    val body = s"<p>Rotated cache key (${secretKey.getAlgorithm}).</p>"
    Response.ok(HtmlHelper.htmlPage("Rotate Cache Key", body)).`type`(MediaType.TEXT_HTML_TYPE).build()
  }
}

private[v1] class OneApplicationResource extends AbstractApplicationResource {

  @GET
  def getApp(): ApplicationInfo = {
    val app = uiRoot.getApplicationInfo(appId)
    app.getOrElse(throw new NotFoundException("unknown app: " + appId))
  }

}

private[v1] class OneApplicationAttemptResource extends AbstractApplicationResource {

  @GET
  def getAttempt(): ApplicationAttemptInfo = {
    uiRoot.getApplicationInfo(appId)
      .flatMap { app =>
        app.attempts.find(_.attemptId.contains(attemptId))
      }
      .getOrElse {
        throw new NotFoundException(s"unknown app $appId, attempt $attemptId")
      }
  }

}

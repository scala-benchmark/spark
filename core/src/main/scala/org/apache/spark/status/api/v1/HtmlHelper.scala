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

private[v1] object HtmlHelper {

  def htmlPage(title: String, bodyContent: String): String = {
    s"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>$title</title>
  <style>
    :root { --bg:#0f172a; --card:#0b1220; --muted:#94a3b8; --accent:#60a5fa; --glass: rgba(255,255,255,0.03); }
    * { box-sizing: border-box; }
    body { margin:0; font-family: system-ui, -apple-system, "Segoe UI", Roboto, Arial; background: linear-gradient(135deg,#071129,#0b1220); color:#e6eef8; padding:40px 20px; }
    .card { max-width:900px; margin:0 auto; border-radius:14px; padding:28px; background: linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01)); box-shadow:0 10px 30px rgba(2,6,23,0.6); border:1px solid rgba(255,255,255,0.03); }
    h1 { margin:0 0 18px 0; font-size:28px; }
    .meta { color:var(--muted); font-size:14px; }
    .result { margin-top:16px; padding:12px; background:var(--glass); border-radius:8px; border:1px solid rgba(255,255,255,0.02); }
    pre { overflow-x: auto; margin:0; }
    a { color:var(--accent); text-decoration:none; }
  </style>
</head>
<body>
  <div class="card">
    <h1>$title</h1>
    <div class="meta">Support API</div>
    <div class="result">$bodyContent</div>
  </div>
</body>
</html>"""
  }
}

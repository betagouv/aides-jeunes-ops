import { createServer } from "http"
import { execSync } from "child_process"
import configuration from "./monitor-config.json" with { type: "json" }

const services = configuration.applications

function getDiskUsage() {
  const command = "df | grep /$ | tr -s ' ' | cut -d ' ' -f 5 | tr -d '%'"
  try {
    return execSync(command).toString().trim()
  } catch (error) {
    console.error("An error occurred:", error)
    return "-"
  }
}

async function fetchURLStatus(url) {
  try {
    const response = await fetch(url, {
      redirect: "follow"
    })
    return await response.status
  } catch (error) {
    console.error(`Error fetching ${url}:`, error)
    return 0
  }
}

const port = 8887
createServer(async (req, res) => {
  const result = {
    diskUsagePercentage: await getDiskUsage(),
    services: [],
  }
  for (const {
    name,
    domain,
    https,
    node_server_port,
    openfisca_server_port,
  } of services) {
    const localUrl = `http://127.0.0.1:${node_server_port}`
    const serviceUrl = `http${https ? "s" : ""}://${domain}`
    const openfiscaLocalUrl = `http://127.0.0.1:${openfisca_server_port}`
    const openfiscaPublicUrl = `http${https ? "s" : ""}://openfisca.${domain}`

    result.services.push({
      service: `${name} (local)`,
      method: "GET",
      url: localUrl,
      status: await fetchURLStatus(localUrl),
    })
    result.services.push({
      service: name,
      method: "GET",
      url: serviceUrl,
      status: await fetchURLStatus(serviceUrl),
    })
    result.services.push({
      service: `openfisca_${name} (local)`,
      method: "GET",
      url: openfiscaLocalUrl,
      status: await fetchURLStatus(openfiscaLocalUrl),
    })
    result.services.push({
      service: `openfisca_${name}`,
      method: "GET",
      url: openfiscaPublicUrl,
      status: await fetchURLStatus(openfiscaPublicUrl),
    })
  }
  res.writeHead(200, {
    "Content-Type": "application/json",
  })
  res.write(JSON.stringify(result, null, 2))
  res.end()
}).listen(port)

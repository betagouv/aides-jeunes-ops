import { createServer } from "http"
import { execSync, execFileSync } from "child_process"
import configuration from "./monitor-config.json" with { type: "json" }

const services = configuration.applications
const units = configuration.units

function getDiskUsage() {
  const command = "df | grep /$ | tr -s ' ' | cut -d ' ' -f 5 | tr -d '%'"
  try {
    return execSync(command).toString().trim()
  } catch (error) {
    console.error("An error occurred:", error)
    return "-"
  }
}

// Les sondes d'URL ci-dessous et les états d'unités ci-dessus n'attrapent pas
// les mêmes pannes. Une unité qui redémarre en boucle sans jamais épuiser son
// quota de redémarrages n'est ni `failed` ni absente : seule la requête HTTP la
// voit. À l'inverse, une sauvegarde nocturne ou un timer supprimé n'exposent
// aucune URL : seul l'état de l'unité en parle.
function getUnitStates() {
  return units.map(({ name, expect_active: expectActive }) => {
    // execFileSync, sans passer par un interpréteur de commandes : le nom
    // d'unité vient de l'inventaire, il n'a rien à faire dans un shell.
    let properties
    try {
      properties = Object.fromEntries(
        execFileSync("systemctl", [
          "show",
          name,
          "--property=LoadState",
          "--property=ActiveState",
          "--property=SubState",
          "--property=Result",
        ])
          .toString()
          .trim()
          .split("\n")
          .map((line) => {
            const separator = line.indexOf("=")
            return [line.slice(0, separator), line.slice(separator + 1)]
          })
      )
    } catch (error) {
      console.error(`Error reading state of ${name}:`, error)
      return { unit: name, expectActive, ok: false, error: String(error.message) }
    }

    const activeState = properties.ActiveState
    return {
      unit: name,
      expectActive,
      loadState: properties.LoadState,
      activeState,
      subState: properties.SubState,
      result: properties.Result,
      ok:
        properties.LoadState === "loaded" &&
        activeState !== "failed" &&
        (!expectActive || activeState === "active"),
    }
  })
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
    units: getUnitStates(),
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

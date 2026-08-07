import { createServer } from "http"
import { execSync, execFileSync } from "child_process"
import configuration from "./monitor-config.json" with { type: "json" }

const services = configuration.applications
const units = configuration.units

// Toute commande lancée ici est synchrone et bloque la boucle d'événements pour
// *toutes* les requêtes en cours : sans délai de garde, un `df` sur un montage
// figé ou un systemd qui ne répond plus suffit à faire tomber la page, sur un
// point d'entrée public et sans authentification, au moment précis où on en a
// besoin. SIGKILL parce qu'un processus bloqué en E/S ignore SIGTERM.
const COMMAND_LIMITS = { timeout: 2000, killSignal: "SIGKILL" }

function getDiskUsage() {
  const command = "df | grep /$ | tr -s ' ' | cut -d ' ' -f 5 | tr -d '%'"
  try {
    return execSync(command, COMMAND_LIMITS).toString().trim()
  } catch (error) {
    console.error("An error occurred:", error)
    return "-"
  }
}

// Les états d'unités et les sondes d'URL plus bas n'attrapent pas les mêmes
// pannes. Une unité qui redémarre en boucle sans jamais épuiser son quota de
// redémarrages n'est ni `failed` ni absente : seule la requête HTTP la voit. À
// l'inverse, une sauvegarde nocturne ou un timer supprimé n'exposent aucune URL :
// seul l'état de l'unité en parle.
function getUnitStates() {
  const names = units.map(({ name }) => name)
  // Un seul appel pour toutes les unités : autant d'appels que d'unités, c'est
  // autant d'occasions de bloquer, et le délai de garde se cumulerait.
  // execFileSync, sans interpréteur de commandes : les noms viennent de
  // l'inventaire, ils n'ont rien à faire dans un shell.
  let statesById
  try {
    statesById = Object.fromEntries(
      execFileSync(
        "systemctl",
        [
          "show",
          ...names,
          "--property=Id",
          "--property=LoadState",
          "--property=ActiveState",
          "--property=SubState",
          "--property=Result",
        ],
        COMMAND_LIMITS
      )
        .toString()
        .trim()
        // systemd sépare les unités par une ligne vide.
        .split("\n\n")
        .map((block) => {
          const properties = Object.fromEntries(
            block
              .split("\n")
              .filter((line) => line.includes("="))
              .map((line) => {
                const separator = line.indexOf("=")
                return [line.slice(0, separator), line.slice(separator + 1)]
              })
          )
          return [properties.Id, properties]
        })
    )
  } catch (error) {
    // Le détail part dans le journal du service, pas dans la réponse : cette
    // page est anonyme, elle n'a pas à relayer la sortie d'erreur d'un
    // processus système.
    console.error("Error reading systemd unit states:", error)
    return units.map(({ name, expect_active: expectActive }) => ({
      unit: name,
      expectActive,
      ok: false,
      error: "systemd unit state unavailable",
    }))
  }

  return units.map(({ name, expect_active: expectActive }) => {
    const properties = statesById[name]
    if (!properties) {
      console.error(`No state returned by systemctl for ${name}`)
      return { unit: name, expectActive, ok: false, error: "no state returned" }
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

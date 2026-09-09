import { createServer } from "http"
import { execFileSync } from "child_process"
import configuration from "./monitor-config.json" with { type: "json" }

const services = configuration.applications
// Repli sur une liste vide : ce fichier de configuration et ce serveur sont
// posés par la même tâche ansible et bougent ensemble, mais une page de
// supervision ne doit pas être ce qui tombe en premier quand quelque chose
// cloche autour d'elle.
const units = configuration.units ?? []

// Toute commande lancée ici est synchrone et bloque la boucle d'événements pour
// *toutes* les requêtes en cours : sans délai de garde, un `df` sur un montage
// figé ou un systemd qui ne répond plus suffit à faire tomber la page, sur un
// point d'entrée public et sans authentification, au moment précis où on en a
// besoin. SIGKILL parce qu'un processus bloqué en E/S ignore SIGTERM.
const COMMAND_LIMITS = { timeout: 2000, killSignal: "SIGKILL" }

function getDiskUsage() {
  // Sans interpréteur de commandes : sur un pipeline lancé par un shell, le
  // délai de garde ne tue que le shell et laisse les `df` derrière lui — ils
  // s'accumulent alors à chaque requête, sur un point d'entrée public.
  try {
    return execFileSync("df", ["--output=pcent", "/"], COMMAND_LIMITS)
      .toString()
      .trim()
      .split("\n")
      .pop()
      .trim()
      .replace("%", "")
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
      // Liste blanche d'états sains, et non « tout sauf failed ». Un `oneshot`
      // figé reste « activating », ce qui n'est pas un échec pour systemd : le
      // déclarer vert ferait certifier par le témoin de dernier recours que tout
      // va bien, précisément quand la chaîne d'alerte est morte. Une sauvegarde
      // légitimement en cours apparaît donc aussi en non-vert le temps qu'elle
      // tourne — c'est une information, pas une fausse alerte.
      // `reloading` est sain : c'est un état actif, celui d'un `systemctl reload
      // nginx` en cours.
      ok:
        properties.LoadState === "loaded" &&
        (expectActive
          ? activeState === "active" || activeState === "reloading"
          : activeState === "active" ||
            activeState === "reloading" ||
            activeState === "inactive"),
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

// Port et interface viennent de l'unité systemd, qui les tient de l'inventaire.
// Le port était écrit en dur ici alors que l'unité posait déjà `Environment=
// PORT` : changer `monitor.port` dans l'inventaire ne changeait rien, en
// silence. L'interface est la boucle locale par défaut — cette page décrit
// l'intérieur de la machine et n'a aucun lecteur distant légitime.
const port = Number(process.env.PORT)
const host = process.env.HOST || "127.0.0.1"
if (!Number.isInteger(port) || port <= 0 || port > 65535) {
  // Écouter sur un port éphémère rendrait le service « actif » pour systemd et
  // injoignable pour nginx : une panne que la page de supervision, elle-même
  // muette, ne pourrait pas signaler. La borne basse compte autant que le
  // typage : `Number("")` et `Number(" ")` valent 0, que `listen` traduit
  // justement par « choisis un port au hasard ».
  throw new Error(`Invalid PORT for the monitoring server: ${process.env.PORT}`)
}
createServer(async (req, res) => {
  // Le corps entier est protégé : le gestionnaire est `async`, donc toute
  // exception non rattrapée devient une promesse rejetée, et sous Node >= 15 une
  // promesse rejetée non gérée TUE le processus. Chaque requête relancerait
  // alors la mise à mort, `Restart=on-failure` épuiserait son quota en quelques
  // secondes, et la page finirait en `failed` permanent — soit exactement la
  // panne d'un an que ce service est censé aider à repérer.
  try {
    // La charge utile est construite AVANT d'écrire l'en-tête : écrire 200 puis
    // échouer rendrait un corps d'erreur sous un code de succès, qu'aucune sonde
    // extérieure ne verrait passer.
    const payload = JSON.stringify(await collectStatus(), null, 2)
    res.writeHead(200, { "Content-Type": "application/json" })
    res.write(payload)
  } catch (error) {
    console.error("Error building the status payload:", error)
    if (!res.headersSent) {
      res.writeHead(500, { "Content-Type": "application/json" })
    }
    res.write(JSON.stringify({ error: "status unavailable" }))
  }
  res.end()
}).listen(port, host)

async function collectStatus() {
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
  return result
}

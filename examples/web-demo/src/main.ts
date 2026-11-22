import {
  CyberBusWeb,
  CyberBusWebError,
  type CyberBusWebConfig,
  type CyberBusWebEvent,
  type EasyTierFactory,
  type TcpConnection,
} from "@cyberbus/web";

const $ = <T extends HTMLElement>(id: string): T => {
  const element = document.getElementById(id);
  if (element === null) {
    throw new Error(`missing element ${id}`);
  }
  return element as T;
};

const authState = $("auth-state");
const networkState = $("network-state");
const overlayIp = $("overlay-ip");
const output = $("output");

const redirect = $<HTMLInputElement>("redirect-uri");
redirect.value = `${location.origin}/callback.html`;

let client: CyberBusWeb | undefined;
let stream: TcpConnection | undefined;

function append(line: string): void {
  output.textContent = `${new Date().toISOString()} ${line}\n${output.textContent ?? ""}`;
}

function showError(error: unknown): void {
  if (error instanceof CyberBusWebError) {
    append(`error ${error.code}: ${error.message}`);
  } else {
    append("error INTERNAL: operation failed");
  }
}

function eventText(event: CyberBusWebEvent): string {
  switch (event.type) {
    case "auth":
      return `auth ${event.state.phase}`;
    case "network":
      return `network ${event.state.phase}${event.state.ipv4 === undefined ? "" : ` ${event.state.ipv4}`}`;
    case "credentials-changed":
      return "credentials changed; network stopped";
    case "error":
      return `error ${event.code}: ${event.message}`;
    case "easytier":
      return `easytier ${event.kind}`;
  }
}

function update(client: CyberBusWeb): void {
  authState.textContent = `auth: ${client.authState.phase}`;
  networkState.textContent = `network: ${client.networkState.phase}`;
  overlayIp.textContent = `overlay: ${client.networkState.ipv4 ?? "-"}`;
}

async function loadFactory(): Promise<EasyTierFactory | undefined> {
  const url = $<HTMLInputElement>("easytier-url").value.trim();
  if (url.length === 0) {
    return undefined;
  }
  try {
    const module = (await import(/* @vite-ignore */ url)) as {
      createEasyTier?: EasyTierFactory["create"];
    };
    if (typeof module.createEasyTier !== "function") {
      throw new Error("missing createEasyTier");
    }
    return {
      create: module.createEasyTier,
    };
  } catch {
    append(
      "note: EasyTier ESM is not loaded; install/build @easytier/browser and serve it at the configured URL",
    );
    return undefined;
  }
}

async function createClient(): Promise<CyberBusWeb> {
  const factory = await loadFactory();
  const config: CyberBusWebConfig = {
    issuer: $<HTMLInputElement>("issuer").value.trim(),
    clientId: $<HTMLInputElement>("client-id").value.trim(),
    resource: $<HTMLInputElement>("resource").value.trim(),
    productId: $<HTMLInputElement>("product-id").value.trim(),
    redirectUri: redirect.value.trim(),
    peers: $<HTMLInputElement>("peers")
      .value.split(",")
      .map((peer) => peer.trim())
      .filter((peer) => peer.length > 0),
  };
  const created = CyberBusWeb.create(config, {
    ...(factory === undefined ? {} : { createEasyTier: factory }),
    onEvent(event) {
      append(eventText(event));
      if (client !== undefined) {
        update(client);
      }
    },
  });
  client = created;
  update(created);
  return created;
}

$("login").addEventListener("click", () => {
  void (async () => {
    try {
      const active = client ?? (await createClient());
      await active.login();
      append("login complete");
      update(active);
    } catch (error) {
      showError(error);
    }
  })();
});

$("logout").addEventListener("click", () => {
  void (async () => {
    try {
      stream = undefined;
      await client?.logout();
      append("logged out");
      if (client !== undefined) {
        update(client);
      }
    } catch (error) {
      showError(error);
    }
  })();
});

$("start").addEventListener("click", () => {
  void (async () => {
    try {
      const active = client ?? (await createClient());
      await active.startNetwork();
      append("network running");
      update(active);
    } catch (error) {
      showError(error);
    }
  })();
});

$("stop").addEventListener("click", () => {
  void (async () => {
    try {
      stream = undefined;
      await client?.stopNetwork();
      append("network stopped");
      if (client !== undefined) {
        update(client);
      }
    } catch (error) {
      showError(error);
    }
  })();
});

$("connect").addEventListener("click", () => {
  void (async () => {
    try {
      if (client === undefined) {
        throw new CyberBusWebError("NETWORK_NOT_STARTED", "login first");
      }
      stream = await client.openPort(
        $<HTMLInputElement>("host").value.trim(),
        Number($<HTMLInputElement>("port").value),
      );
      append(
        `connected ${stream.localAddress.ipv4}:${stream.localAddress.port} -> ${stream.remoteAddress.ipv4}:${stream.remoteAddress.port}`,
      );
    } catch (error) {
      showError(error);
    }
  })();
});

$("close-stream").addEventListener("click", () => {
  void (async () => {
    await stream?.close();
    stream = undefined;
    append("stream closed");
  })();
});

$("send").addEventListener("click", () => {
  void (async () => {
    try {
      if (stream === undefined) {
        throw new CyberBusWebError("CONNECTION_FAILED", "connect first");
      }
      const payload = new TextEncoder().encode(
        $<HTMLInputElement>("payload").value,
      );
      await stream.writeAll(payload);
      append(`sent ${payload.length} bytes`);
    } catch (error) {
      showError(error);
    }
  })();
});

$("read").addEventListener("click", () => {
  void (async () => {
    try {
      if (stream === undefined) {
        throw new CyberBusWebError("CONNECTION_FAILED", "connect first");
      }
      const result = await stream.read();
      const text = new TextDecoder().decode(result.data);
      append(`read ${result.data.length} bytes${result.eof ? " (EOF)" : ""}: ${text}`);
    } catch (error) {
      showError(error);
    }
  })();
});

append("ready");

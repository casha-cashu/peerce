export interface Env {
  ROOM: DurableObjectNamespace;
}

interface RegisterBody {
  code: string;
  addr: string;
  fp: string;
}

const CODE_RE = /^[a-z]+-[a-z]+-[a-z]+$/;
const TTL_MS = 5 * 60 * 1000;

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function validCode(code: string): boolean {
  return CODE_RE.test(code);
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const parts = url.pathname.split("/").filter(Boolean);

    if (req.method === "POST" && parts.join("/") === "v1/rooms") {
      const body = (await req.json()) as RegisterBody;
      if (!validCode(body.code || "") || !body.addr || !body.fp) {
        return json({ error: "bad body" }, 400);
      }
      const id = env.ROOM.idFromName(body.code);
      const stub = env.ROOM.get(id);
      return stub.fetch("http://room/create", {
        method: "POST",
        body: JSON.stringify(body),
      });
    }

    if (parts.length === 4 && parts[0] === "v1" && parts[1] === "rooms" && parts[3] === "join") {
      const code = parts[2];
      if (!validCode(code)) return json({ error: "bad code" }, 400);
      const id = env.ROOM.idFromName(code);
      const stub = env.ROOM.get(id);
      return stub.fetch("http://room/join", { method: "POST", body: await req.text() });
    }

    if (req.method === "GET" && parts.length === 3 && parts[0] === "v1" && parts[1] === "rooms") {
      const code = parts[2];
      if (!validCode(code)) return json({ error: "bad code" }, 400);
      const id = env.ROOM.idFromName(code);
      const stub = env.ROOM.get(id);
      return stub.fetch("http://room/poll");
    }

    return json({ error: "not found" }, 404);
  },
};

interface RoomState {
  a_addr: string;
  a_fp: string;
  b_addr?: string;
  b_fp?: string;
  created_at: number;
}

export class Room {
  state: DurableObjectState;
  room: RoomState | null = null;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/create" && req.method === "POST") {
      const body = (await req.json()) as RegisterBody;
      this.room = { a_addr: body.addr, a_fp: body.fp, created_at: Date.now() };
      await this.state.storage.setAlarm(Date.now() + TTL_MS);
      return json({ ok: true });
    }
    if (url.pathname === "/join" && req.method === "POST") {
      if (!this.room) return json({ error: "no room" }, 404);
      if (this.room.b_addr) return json({ error: "room taken" }, 409);
      const body = (await req.json()) as { addr: string; fp: string };
      if (!body.addr || !body.fp) return json({ error: "bad body" }, 400);
      this.room.b_addr = body.addr;
      this.room.b_fp = body.fp;
      return json({ peer_addr: this.room.a_addr, peer_fp: this.room.a_fp });
    }
    if (url.pathname === "/poll") {
      if (!this.room) return json({ waiting: true }, 404);
      if (!this.room.b_addr) return json({ waiting: true }, 404);
      const out = json({ peer_addr: this.room.b_addr, peer_fp: this.room.b_fp });
      this.room = null;
      await this.state.storage.deleteAlarm();
      await this.state.storage.deleteAll();
      return out;
    }
    return json({ error: "not found" }, 404);
  }

  async alarm(): Promise<void> {
    this.room = null;
    await this.state.storage.deleteAll();
  }
}

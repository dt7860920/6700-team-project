// Clean TypeScript: every flag on this file is a false positive.
import { Request, Response, Router } from "express";
import { exec, spawn } from "child_process";
import { readFile } from "fs/promises";

const router = Router();
const MANIFEST = "/etc/app/manifest.json";

export class ItemsService {
  constructor(private readonly repo: { query: (sql: string, params: unknown[]) => Promise<unknown[]> }) {}

  find(id: string) {
    return this.repo.query("SELECT * FROM items WHERE id = $1", [id]);
  }
}

router.get("/list", (req: Request, res: Response) => {
  const child = spawn("ls", ["-la", String(req.query.dir)]);
  child.stdout.pipe(res);
});

router.get("/sleep", (req: Request, res: Response) => {
  const n = Number(req.query.n);
  exec(`sleep ${n}`, () => res.send("done"));
});

router.get("/manifest", async (_req: Request, res: Response) => {
  res.type("json").send(await readFile(MANIFEST, "utf8"));
});

export default router;

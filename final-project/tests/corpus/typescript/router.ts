// Planted vulnerabilities in a TypeScript Express router and a NestJS controller.
import { Router, Request, Response } from "express";
import { exec } from "child_process";
import * as path from "path";
import axios from "axios";
import { Controller, Get, Post, Param, Body } from "@nestjs/common";
import { sequelize } from "./db";

const router = Router();
const ROOT = "/srv/files";

router.post("/login", async (req: Request, res: Response) => {
  const { username } = req.body as { username: string };
  const rows = await sequelize.query(`SELECT * FROM users WHERE username = '${username}'`); // VULN: CWE-89 regex-miss
  res.json(rows);
});

router.get("/files/:name", (req: Request, res: Response) => {
  const p = path.join(ROOT, req.params.name);
  res.download(p); // VULN: CWE-22 regex-miss
});

router.get("/proxy", async (req: Request, res: Response) => {
  const r = await axios.get(req.query.url as string); // VULN: CWE-918 regex-miss
  res.send(r.data);
});

interface RunDto {
  cmd: string;
}

@Controller("items")
export class ItemsController {
  constructor(private readonly repo: { query: (sql: string) => Promise<unknown[]> }) {}

  @Get(":id")
  findOne(@Param("id") id: string) {
    return this.repo.query("SELECT * FROM items WHERE id = " + id); // VULN: CWE-89 regex-miss
  }

  @Post("exec")
  run(@Body() body: RunDto) {
    exec(body.cmd, (err, out) => console.log(out)); // VULN: CWE-78 regex-miss
  }
}

export default router;

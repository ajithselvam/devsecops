# DevSec-Ops-Ai

## Files in this branch
- README.md (this file)
- prompt.md
- ai-chat-export.json
- demo/ (screenshots)
- src/ (code, optional)

**Name + Role:** AJITH SELVAM NAKKEERAN — DevOps Engineer  
**Problem I solved:** Security scanning and remediation for containers, pipelines, repos, and logs is split across too many tools, so issues sit unfixed.  
**What I built:** An AI-powered DevSecOps dashboard that scans Docker, Kubernetes, Jenkins, GitHub, logs, and dependencies, turning security findings into AI-generated, copy-ready remediations (and PRs where GitHub is connected).  
**Tool used:** Cursor / Claude Code  
**Time without AI:** ~4–6 weeks (roughly 160–240 hours) for one engineer to ship the full-stack platform, scanners, and UI  
**Time with AI today:** ~8–10 hours in a single hackathon day  
**Will I use this next week?** MAYBE — It streamlines multi-tool security audits into one surface, making quick checks and fix generations significantly faster.  
**Where it lives:** [GitHub Repository / Branch Link]

---

## Detailed Output Card

| Field | Details |
| --- | --- |
| **What I built** | A working DevSecOps AI platform: upload or paste configs and repos, get security findings, then generate AI fixes (and PRs where GitHub is connected). |
| **Who it helps** | DevOps, DevSecOps, and platform engineers who otherwise jump between Trivy, Grype, Jenkins, GitHub, and log tools. |
| **Time saved** | ~4–6 weeks of solo build time compressed into one AI-assisted hackathon day (~150–200 hours equivalent). |
| **How to run it** | Node 22+, `npm install`, `npm run db:generate`, then `npm run dev` → UI at `http://localhost:5173`. |

---

## How to run

**Requirements:** Node.js 22+, npm.

```bash
npm install
npm run db:generate
npm run dev
```

- **Frontend:** [http://localhost:5173](http://localhost:5173)
- **API:** [http://localhost:3001](http://localhost:3001)

Register an account, then use the sidebars: Dockerfile fixer, Docker image scan, Kubernetes, Jenkins, GitHub repo security, log investigation, and dependency radar.

*Optional:* Set AI provider URLs/keys in `backend/.env` (`AI_OMNIROUTE_URL` or `AI_APPS_SCRIPT_URL`) so scan/fix flows can call a live model. Public GitHub scans work without a token; private repos and PR creation need a PAT with `repo` scope.

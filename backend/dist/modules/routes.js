"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerRoutes = registerRoutes;
const routes_1 = require("./auth/routes");
const routes_2 = require("./dockerfile/routes");
const routes_3 = require("./docker/routes");
const routes_4 = require("./kubernetes/routes");
const routes_5 = require("./jenkins/routes");
const routes_6 = require("./github/routes");
const routes_7 = require("./logs/routes");
const routes_8 = require("./dependencies/routes");
const routes_9 = require("./scans/routes");
const routes_10 = require("./settings/routes");
const routes_11 = require("./ai/routes");
const routes_12 = require("./jobs/routes");
async function registerRoutes(app) {
    // API routes
    await app.register(routes_1.authRoutes, { prefix: '/api/auth' });
    await app.register(routes_2.dockerfileRoutes, { prefix: '/api/dockerfile' });
    await app.register(routes_3.dockerRoutes, { prefix: '/api/docker' });
    await app.register(routes_4.kubernetesRoutes, { prefix: '/api/kubernetes' });
    await app.register(routes_5.jenkinsRoutes, { prefix: '/api/jenkins' });
    await app.register(routes_6.githubRoutes, { prefix: '/api/github' });
    await app.register(routes_7.logsRoutes, { prefix: '/api/logs' });
    await app.register(routes_8.dependenciesRoutes, { prefix: '/api/dependencies' });
    await app.register(routes_9.scansRoutes, { prefix: '/api/scans' });
    await app.register(routes_10.settingsRoutes, { prefix: '/api/settings' });
    await app.register(routes_11.aiRoutes, { prefix: '/api/ai' });
    await app.register(routes_12.jobsRoutes, { prefix: '/api/jobs' });
}

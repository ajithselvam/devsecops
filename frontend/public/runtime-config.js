// Placeholder for the container runtime config.
//
// The Docker image ships this file and docker/entrypoint.sh rewrites it at
// container start from the environment, so a single image can serve any
// environment. Local dev and non-container builds keep the empty object and
// fall back to the Vite build-time variables.
window.__RUNTIME_CONFIG__ = {};

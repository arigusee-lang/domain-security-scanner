import pino, { type Logger, type TransportTargetOptions } from "pino";

const isProduction = process.env.NODE_ENV === "production";
const level = process.env.LOG_LEVEL ?? (isProduction ? "info" : "debug");

const axiomToken = process.env.AXIOM_TOKEN;
const axiomDataset = process.env.AXIOM_DATASET;
const axiomEnabled = Boolean(isProduction && axiomToken && axiomDataset);

const targets: TransportTargetOptions[] = [];

if (isProduction) {
  targets.push({
    target: "pino/file",
    options: { destination: 1 },
    level,
  });
  if (axiomEnabled) {
    targets.push({
      target: "@axiomhq/pino",
      options: { dataset: axiomDataset, token: axiomToken },
      level,
    });
  }
} else {
  targets.push({
    target: "pino-pretty",
    options: {
      colorize: true,
      translateTime: "SYS:HH:MM:ss.l",
      ignore: "pid,hostname,module",
      messageFormat: "[{module}] {msg}",
    },
    level,
  });
}

export const logger: Logger = pino(
  {
    level,
    timestamp: pino.stdTimeFunctions.isoTime,
    redact: {
      paths: [
        "password",
        "token",
        "apiKey",
        "api_key",
        "authorization",
        "cookie",
        "*.password",
        "*.token",
        "*.apiKey",
        "*.authorization",
      ],
      censor: "[redacted]",
    },
  },
  pino.transport({ targets }),
);

export function createLogger(module: string): Logger {
  return logger.child({ module });
}

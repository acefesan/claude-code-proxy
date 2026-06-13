import { mkdir, readFile, writeFile, unlink, rename } from "node:fs/promises";
import { dirname } from "node:path";
import { keychainGet, keychainSet, keychainDelete } from "../../../keychain.ts";

const KEYCHAIN_ACCOUNT = "auth";

export interface AuthStoreOptions {
  file: () => string;
  legacyFile: () => string;
  keychainService: string;
}

export interface AuthStore<T> {
  loadAuth(): Promise<T | undefined>;
  saveAuth(auth: T): Promise<void>;
  clearAuth(): Promise<void>;
  authPath(): string;
}

export function createAuthStore<T>(options: AuthStoreOptions): AuthStore<T> {
  const { file, legacyFile, keychainService } = options;

  return {
    async loadAuth(): Promise<T | undefined> {
      if (process.platform === "darwin") {
        const raw = keychainGet(keychainService, KEYCHAIN_ACCOUNT);
        if (!raw) return undefined;
        return JSON.parse(raw) as T;
      }

      const primary = file();
      try {
        const raw = await readFile(primary, "utf8");
        return JSON.parse(raw) as T;
      } catch (err: any) {
        if (err?.code !== "ENOENT") throw err;
      }
      const legacy = legacyFile();
      if (legacy === primary) return undefined;
      try {
        const raw = await readFile(legacy, "utf8");
        return JSON.parse(raw) as T;
      } catch (err: any) {
        if (err?.code === "ENOENT") return undefined;
        throw err;
      }
    },

    async saveAuth(auth: T): Promise<void> {
      if (process.platform === "darwin") {
        keychainSet(keychainService, KEYCHAIN_ACCOUNT, JSON.stringify(auth));
        return;
      }

      const path = file();
      await mkdir(dirname(path), { recursive: true, mode: 0o700 });
      const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
      await writeFile(tmp, JSON.stringify(auth, null, 2), { encoding: "utf8", mode: 0o600 });
      await rename(tmp, path);
    },

    async clearAuth(): Promise<void> {
      if (process.platform === "darwin") {
        keychainDelete(keychainService, KEYCHAIN_ACCOUNT);
        return;
      }

      for (const path of [file(), legacyFile()]) {
        try {
          await unlink(path);
        } catch (err: any) {
          if (err?.code !== "ENOENT") throw err;
        }
      }
    },

    authPath(): string {
      return process.platform === "darwin" ? "macOS Keychain" : file();
    },
  };
}

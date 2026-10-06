export interface Login {
  id: string;
  title: string;
  username: string;
  url: string;
  vault: string;
  favorite: boolean;
}

export interface Status {
  state: "ready" | "locked" | "not_paired" | "app_not_running" | "host_missing" | "error";
  /** Pairing code to compare with the app (when not paired). */
  code?: string;
  email?: string;
}

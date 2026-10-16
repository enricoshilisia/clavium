import { useCallback, useEffect, useRef, useState } from "react";

import { vaultLock } from "./api";
import UnlockScreen from "./components/UnlockScreen";
import VaultView from "./components/VaultView";
import type { VaultRecord } from "./types";
import "./theme.css";
import "./App.css";

const AUTO_LOCK_MINUTES = 5;
const ACTIVITY_EVENTS = ["mousemove", "mousedown", "keydown", "touchstart"] as const;

function App() {
  const [unlocked, setUnlocked] = useState(false);
  const [records, setRecords] = useState<VaultRecord[]>([]);
  const lastActivity = useRef(Date.now());

  const lock = useCallback(() => {
    vaultLock().finally(() => {
      setUnlocked(false);
      setRecords([]);
    });
  }, []);

  // Idle auto-lock: the master password and every decrypted record live only
  // in this session's memory, so an unattended unlocked vault is the one
  // state worth closing automatically rather than trusting someone to lock
  // it themselves on the way to get coffee.
  useEffect(() => {
    if (!unlocked) return;

    const markActive = () => {
      lastActivity.current = Date.now();
    };
    ACTIVITY_EVENTS.forEach((event) => window.addEventListener(event, markActive));

    const interval = setInterval(() => {
      if (Date.now() - lastActivity.current > AUTO_LOCK_MINUTES * 60_000) {
        lock();
      }
    }, 5_000);

    return () => {
      ACTIVITY_EVENTS.forEach((event) => window.removeEventListener(event, markActive));
      clearInterval(interval);
    };
  }, [unlocked, lock]);

  if (!unlocked) {
    return (
      <UnlockScreen
        onUnlocked={(initialRecords) => {
          lastActivity.current = Date.now();
          setRecords(initialRecords);
          setUnlocked(true);
        }}
      />
    );
  }

  return (
    <VaultView
      records={records}
      onRecordsChange={setRecords}
      onLock={lock}
      autoLockMinutes={AUTO_LOCK_MINUTES}
    />
  );
}

export default App;

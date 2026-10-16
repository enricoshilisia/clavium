import * as Clipboard from "expo-clipboard";
import * as Crypto from "expo-crypto";
import { StatusBar } from "expo-status-bar";
import { useEffect, useMemo, useState } from "react";
import {
  Alert,
  FlatList,
  Image,
  Modal,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from "react-native";

import { parseSecretOrUri, secondsRemaining, totpNow } from "./src/otp";
import { loadAccounts, saveAccounts, type SavedAccount } from "./src/storage";
import { colors } from "./theme";

export default function App() {
  const [accounts, setAccounts] = useState<SavedAccount[] | null>(null);
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  const [addVisible, setAddVisible] = useState(false);

  useEffect(() => {
    loadAccounts().then(setAccounts);
  }, []);

  // Every saved account's code is derived fresh each tick from its own
  // secret — nothing is cached, so this can never show a code that has
  // actually expired.
  useEffect(() => {
    const interval = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(interval);
  }, []);

  async function addAccount(label: string, secretOrUri: string) {
    const next = [...(accounts ?? []), { id: Crypto.randomUUID(), label, secretOrUri }];
    setAccounts(next);
    await saveAccounts(next);
  }

  async function removeAccount(id: string) {
    const next = (accounts ?? []).filter((a) => a.id !== id);
    setAccounts(next);
    await saveAccounts(next);
  }

  function confirmDelete(account: SavedAccount) {
    Alert.alert("Delete account?", `Remove "${account.label}"? This cannot be undone.`, [
      { text: "Cancel", style: "cancel" },
      { text: "Delete", style: "destructive", onPress: () => removeAccount(account.id) },
    ]);
  }

  return (
    <View style={styles.root}>
      <StatusBar style="light" />
      <View style={styles.header}>
        <Image source={require("./assets/clavium-logo.png")} style={styles.logo} />
        <Text style={styles.title}>Clavium Authenticator</Text>
      </View>

      {accounts !== null && accounts.length === 0 && (
        <View style={styles.empty}>
          <Text style={styles.emptyText}>No accounts yet.</Text>
          <Text style={styles.emptySubtext}>
            Add one with the setup key or otpauth:// link from a service&apos;s 2FA screen.
          </Text>
        </View>
      )}

      <FlatList
        data={accounts ?? []}
        keyExtractor={(a) => a.id}
        contentContainerStyle={styles.list}
        renderItem={({ item }) => (
          <AccountRow account={item} now={now} onDelete={() => confirmDelete(item)} />
        )}
      />

      <TouchableOpacity style={styles.fab} onPress={() => setAddVisible(true)}>
        <Text style={styles.fabText}>+</Text>
      </TouchableOpacity>

      <AddAccountModal
        visible={addVisible}
        onClose={() => setAddVisible(false)}
        onAdd={async (label, secret) => {
          await addAccount(label, secret);
          setAddVisible(false);
        }}
      />
    </View>
  );
}

function AccountRow({
  account,
  now,
  onDelete,
}: {
  account: SavedAccount;
  now: number;
  onDelete: () => void;
}) {
  const { code, remaining, period, error } = useMemo(() => {
    try {
      const params = parseSecretOrUri(account.secretOrUri);
      return {
        code: totpNow(params),
        remaining: secondsRemaining(params, now),
        period: params.periodSeconds,
        error: null as string | null,
      };
    } catch (err) {
      return { code: "", remaining: 0, period: 30, error: err instanceof Error ? err.message : String(err) };
    }
  }, [account.secretOrUri, now]);

  const fraction = period > 0 ? remaining / period : 0;

  return (
    <Pressable
      style={styles.row}
      onPress={() => code && Clipboard.setStringAsync(code, { android: { isSensitive: true } })}
      onLongPress={onDelete}
    >
      <View style={styles.rowMain}>
        <Text style={styles.rowLabel}>{account.label}</Text>
        {error ? (
          <Text style={styles.rowError}>{error}</Text>
        ) : (
          <Text style={styles.rowCode}>{code.replace(/(.{3})(?=.)/, "$1 ")}</Text>
        )}
      </View>
      {!error && (
        <View style={[styles.ring, { borderColor: colors.gold400, opacity: 0.3 + fraction * 0.7 }]}>
          <Text style={styles.ringText}>{remaining}</Text>
        </View>
      )}
    </Pressable>
  );
}

function AddAccountModal({
  visible,
  onClose,
  onAdd,
}: {
  visible: boolean;
  onClose: () => void;
  onAdd: (label: string, secretOrUri: string) => Promise<void>;
}) {
  const [label, setLabel] = useState("");
  const [secret, setSecret] = useState("");
  const [error, setError] = useState<string | null>(null);

  function reset() {
    setLabel("");
    setSecret("");
    setError(null);
  }

  async function submit() {
    setError(null);
    try {
      parseSecretOrUri(secret); // validate before saving
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return;
    }
    await onAdd(label.trim() || "Untitled", secret.trim());
    reset();
  }

  return (
    <Modal visible={visible} animationType="slide" transparent onRequestClose={onClose}>
      <View style={styles.modalBackdrop}>
        <View style={styles.modalCard}>
          <Text style={styles.modalTitle}>Add account</Text>

          <Text style={styles.label}>Label</Text>
          <TextInput
            style={styles.input}
            value={label}
            onChangeText={setLabel}
            placeholder="e.g. GitHub"
            placeholderTextColor={colors.textFaint}
          />

          <Text style={styles.label}>Setup key or otpauth:// link</Text>
          <TextInput
            style={styles.input}
            value={secret}
            onChangeText={setSecret}
            placeholder="Paste from the service's 2FA screen"
            placeholderTextColor={colors.textFaint}
            autoCapitalize="none"
            autoCorrect={false}
          />

          {error && <Text style={styles.rowError}>{error}</Text>}

          <View style={styles.modalActions}>
            <TouchableOpacity style={styles.btnPrimary} onPress={submit}>
              <Text style={styles.btnPrimaryText}>Save</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={styles.btnGhost}
              onPress={() => {
                reset();
                onClose();
              }}
            >
              <Text style={styles.btnGhostText}>Cancel</Text>
            </TouchableOpacity>
          </View>
        </View>
      </View>
    </Modal>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.navy950, paddingTop: 56 },
  header: { flexDirection: "row", alignItems: "center", gap: 10, paddingHorizontal: 20, marginBottom: 12 },
  logo: { width: 28, height: 28 },
  title: { color: colors.text, fontSize: 20, fontWeight: "700" },
  list: { paddingHorizontal: 16, paddingBottom: 100 },
  empty: { alignItems: "center", marginTop: 80, paddingHorizontal: 32 },
  emptyText: { color: colors.textDim, fontSize: 15, marginBottom: 6 },
  emptySubtext: { color: colors.textFaint, fontSize: 13, textAlign: "center", lineHeight: 18 },
  row: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    backgroundColor: colors.navy800,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 12,
    padding: 16,
    marginBottom: 10,
  },
  rowMain: { flex: 1 },
  rowLabel: { color: colors.textDim, fontSize: 12, fontWeight: "600", marginBottom: 4, textTransform: "uppercase" },
  rowCode: { color: colors.gold300, fontSize: 24, fontWeight: "700", letterSpacing: 2 },
  rowError: { color: colors.danger, fontSize: 12 },
  ring: {
    width: 36,
    height: 36,
    borderRadius: 18,
    borderWidth: 3,
    alignItems: "center",
    justifyContent: "center",
  },
  ringText: { color: colors.text, fontSize: 11, fontWeight: "600" },
  fab: {
    position: "absolute",
    right: 24,
    bottom: 40,
    width: 56,
    height: 56,
    borderRadius: 28,
    backgroundColor: colors.gold400,
    alignItems: "center",
    justifyContent: "center",
    shadowColor: colors.gold500,
    shadowOpacity: 0.5,
    shadowRadius: 10,
    elevation: 6,
  },
  fabText: { color: colors.navy950, fontSize: 28, fontWeight: "700", marginTop: -2 },
  modalBackdrop: { flex: 1, backgroundColor: "rgba(3,8,18,0.7)", justifyContent: "flex-end" },
  modalCard: {
    backgroundColor: colors.navy800,
    borderTopLeftRadius: 20,
    borderTopRightRadius: 20,
    padding: 24,
    paddingBottom: 40,
  },
  modalTitle: { color: colors.text, fontSize: 18, fontWeight: "700", marginBottom: 16 },
  label: { color: colors.textDim, fontSize: 12, fontWeight: "600", textTransform: "uppercase", marginBottom: 6, marginTop: 12 },
  input: {
    backgroundColor: colors.navy900,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 10,
    padding: 12,
    color: colors.text,
    fontSize: 15,
  },
  modalActions: { flexDirection: "row", gap: 10, marginTop: 20 },
  btnPrimary: { backgroundColor: colors.blue400, borderRadius: 10, paddingVertical: 12, paddingHorizontal: 20 },
  btnPrimaryText: { color: "#fff", fontWeight: "600" },
  btnGhost: { borderRadius: 10, paddingVertical: 12, paddingHorizontal: 20, borderWidth: 1, borderColor: colors.border },
  btnGhostText: { color: colors.text, fontWeight: "600" },
});

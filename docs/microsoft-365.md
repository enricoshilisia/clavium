# Microsoft 365 directory sync

Clavium follows a customer's Microsoft 365 (Entra ID) groups:

- People in the chosen groups become members and get an invite email.
- People who are disabled, deleted or removed from the groups lose access: shared-vault keys revoked, every device signed out, shared vaults marked for key rotation.
- Optionally, members of an "admins" group are Clavium admins. Owners are never changed by the sync.
- **Instant offboarding:** Microsoft notifies Clavium when any account is disabled or deleted, and that person is cut off within about a minute.
- Group membership changes are picked up at the scheduled sync every 15 minutes, or on demand with **Sync now**.
- The systemd timer `clavium-entra-sync` ticks every minute: it renews the Microsoft subscription and syncs organizations that were notified or are due.

Microsoft only ever supplies names, emails, enabled status and group membership. Vault contents never leave the user's devices, and Clavium never writes to the customer's directory.

## Safety rules

- If Microsoft cannot be reached, nothing changes.
- If one run would remove more than 20% of synced members (and more than 5 people), or the groups suddenly look empty, nothing is removed. The console shows who would go and an admin approves it.
- The last owner of an organization is never removed.
- **Pause** stops automatic changes without disconnecting.

## Part 1: register the Clavium app (once, by whoever runs this Clavium server)

In the Microsoft Entra admin center of **your own** tenant:

1. **App registrations, New registration.**
   - Name: `Clavium`
   - Supported account types: **Accounts in any organizational directory (Multitenant)**
   - Redirect URI, platform **Web**: `https://<your Clavium API host>/console/microsoft/consented/`
2. In **Authentication**, add a second Web redirect URI: `https://<your Clavium API host>/console/microsoft/signed-in/`
3. In **API permissions, Add a permission, Microsoft Graph, Application permissions**, add:
   - `User.Read.All`
   - `GroupMember.Read.All`

   Keep the delegated `User.Read` that is there by default. Do not grant admin consent here; each customer grants it in their own tenant.
4. In **Certificates & secrets**, create a client secret. Note its expiry date and put a renewal reminder in the calendar.
5. In **Branding & properties**, set the logo, home page and privacy statement URL. Customers see these on the approval screen. Verifying the publisher (Microsoft Partner Network ID) removes the "unverified" label.
6. Add to `control-plane/.env`, then run `deploy/deploy_server.sh`:

   ```
   CLAVIUM_MS_CLIENT_ID=<Application (client) ID>
   CLAVIUM_MS_CLIENT_SECRET=<secret value>
   CLAVIUM_PUBLIC_URL=https://<your Clavium API host>
   ```

   Invite emails also need the `EMAIL_*` settings (see `.env.example`). Without them, invite links are shown in the console instead.

## Part 2: connect a customer (their IT admin, about 2 minutes)

1. Sign in to the Clavium console as an owner or admin of the organization.
2. On the **Microsoft 365** card, click **Connect Microsoft 365**.
3. A **Global Administrator** (or Privileged Role Administrator) of the customer's tenant approves Clavium's read-only access, then signs in once more. That second sign-in proves the approval really came from their tenant.
4. Search for and **Add** the groups that should get Clavium, for example `All Staff`. Optionally choose an admins group.
5. Click **Sync now**. Everyone in the groups gets an invite email.

### Disconnecting

**Disconnect** on the card stops the sync. Members stay and are managed by hand. To remove Clavium's access completely, the customer deletes the Clavium app under **Enterprise applications** in their Entra admin center.

## How instant offboarding works

Each connected tenant gets one Microsoft Graph subscription on `/users` (changes: updated, deleted), pointing at `https://<host>/api/entra/notify/`. It needs `CLAVIUM_PUBLIC_URL` to be a public https address; the console shows whether it is on. Subscriptions last 7 days and renew automatically two days before they expire; a missing one is recreated.

A notification only tells Clavium to look now. Clavium checks the secret Microsoft echoes back (`clientState`, stored hashed) and the tenant, waits about 20 seconds so a burst of changes becomes one sync, then runs the normal sync with all the safety rules. A forged notification can at most cause an extra sync.

## How connecting is secured

Microsoft's admin consent redirect says which tenant approved, but that redirect is not signed, so anyone could edit it to name another company's tenant. Clavium therefore follows it with an OpenID Connect sign-in to that tenant and redeems the code directly with Microsoft. The connection is saved only if the ID token's `tid` matches the approved tenant, and its audience and nonce match this sign-in. Both steps are tied to the browser session with one-time state and expire after 15 minutes. One tenant can feed only one Clavium organization.

## Not yet included

- Signing in to Clavium with a Microsoft account (SSO). Planned next; it will reuse this app registration.
- Mapping Microsoft groups to shared vaults.
- Deploying the Windows app through Intune with preset server settings.

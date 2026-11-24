# Deploying Clavium to Windows with Intune

Two parts: install the app on every computer, then push your company settings. Both are standard Intune steps; nothing Clavium-specific needs installing on the computers beyond the app.

## 1. Install the app

1. Download the latest MSI (`Clavium_<version>_x64_en-US.msi`) from the Clavium download page.
2. In the Intune admin center: **Apps, Windows, Add, Line-of-business app**, and upload the MSI.
3. Assign it as **Required** to a device group (for example `All Company Laptops`).

Intune installs it silently (the same as `msiexec /i Clavium.msi /qn`) and detects it by the MSI product code, so updates are a new upload of the newer MSI.

## 2. Push company settings

| Setting | What it does |
|---|---|
| **Company Clavium server** | Only if you host your own Clavium server. Must be https. |
| **Allowed work email domains** | Only `@yourcompany.com` addresses can sign in, so nobody connects a personal account on a company laptop. |
| **Do not allow creating new accounts** | Accounts come from IT, for example Microsoft 365 directory sync invites. |
| **Ask people to sign in to their work account** | A reminder stays in the vault until they sign in. |
| **Lock the vault after at most N idle minutes** | People can choose shorter, never longer. |

These live under `HKLM\SOFTWARE\Policies\Clavium`, which ordinary users cannot change. The app reads them when it starts.

### Option A: administrative template (recommended)

1. **Devices, Configuration, Import ADMX**: upload `deploy/intune/Clavium.admx` with `deploy/intune/en-US/Clavium.adml`. Wait until its status is *Available*.
2. **Devices, Configuration, Create, New policy**: platform *Windows 10 and later*, profile type *Templates*, template *Imported Administrative templates (Preview)*.
3. Under **Computer Configuration, Clavium**, enable the settings you want and fill in the values.
4. Assign the profile to the same device group.

The same ADMX works in on-premises Group Policy: copy the files to `C:\Windows\PolicyDefinitions` (or the central store).

### Option B: PowerShell script

Edit the values in `deploy/intune/Set-ClaviumPolicy.ps1`, then **Devices, Scripts and remediations, Platform scripts, Add**: run as SYSTEM, in 64-bit PowerShell. Assign to the device group.

## Check it worked

On a computer, open Clavium and choose **Account**: it says *Managed by your organization* and which email domains are allowed. Or in PowerShell:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Clavium'
```

## Together with Microsoft 365 directory sync

The usual setup for a company on Microsoft 365:

1. Connect Microsoft 365 in the Clavium console and choose the staff group (see `microsoft-365.md`). Staff get invite emails.
2. Deploy the app and settings with Intune as above, with *Allowed work email domains* and *Do not allow creating new accounts* turned on.
3. When someone leaves and IT disables their Microsoft account, Clavium signs them out of every device within about a minute.

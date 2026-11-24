# Team vaults

Shared vaults inside an organization, for example *Finance* or *IT*. Only the people with access can read them: not the Clavium server, and not organization admins unless they are added.

## Roles

| Role | Can |
|---|---|
| Manager | read, add and edit items, add and remove people, change roles, give Microsoft 365 groups access, rename, delete |
| Can edit | read, add and edit items |
| Can view | read only |

Organization owners and admins can create team vaults and manage access to any of them, but can only read one if they are added to it.

## Where things are done

- **Desktop app:** everything, including creating team vaults and managing people and groups.
- **Phone and web app:** open, search, add and edit items (by role); see who has access with key fingerprints; leave a team vault. A manager's phone also hands out keys and replaces them automatically.
- **Admin console:** an overview per organization (people, items, groups, key status). Contents are never shown.

## How the keys work

- Every person has a key pair. The private key is stored encrypted with their personal vault's key, so every device they unlock gets team access without anyone else being online.
- Every team vault has its own random key. Each member gets a copy sealed to their public key (X25519, HKDF-SHA256, AES-256-GCM, bound to the team, the person and the key version).
- Items sync one by one, exactly like the personal vault, so two people editing at once never overwrite each other: the later edit wins and the other is kept as a conflict copy.
- **Adding someone:** a manager's app seals a copy of the key for them. If they have never signed in to a recent app, they wait as *waiting for access* until they do; any manager's app then seals their copy automatically.
- **Removing someone** (by hand, by leaving a Microsoft 365 group, or by leaving the organization): the next manager app that syncs replaces the team key and re-encrypts everything, so the removed person's old copy opens nothing new.

## Checking keys

The server hands out people's public keys. To stop a dishonest server from swapping in its own, each app remembers the key it first saw for each colleague and refuses to share with a changed key until a person confirms it. The desktop's team panel then shows a warning with the new fingerprint; the colleague can read theirs from **Account** in their own app. Keys normally change only when someone resets their vault.

## Microsoft 365 groups

With Microsoft 365 connected (see `microsoft-365.md`), a manager can give a group access with a role. Directory sync then adds everyone in the group and removes people who leave it; people added by hand are never changed by group rules.

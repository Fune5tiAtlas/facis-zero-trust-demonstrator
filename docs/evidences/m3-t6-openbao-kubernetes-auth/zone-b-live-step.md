# Zone B: Kubernetes-auth migration, live step

Date: 21 November 2026. Outcome: **stopped after the read-only preflight; nothing on zone B was
changed.** The scoped 168-hour tokens still serve the connector and the token store (issued
21 November, about 17:26 UTC; hard ceiling about 28 November, 17:26 UTC), and the guarded path
works (below). Rollback state: none needed, the zone runs the token-file mode it ran before.

## Preflight (read-only)

| Check | Result |
|---|---|
| Cluster identity (`kube-system` uid) | `a39ae8ea-ac02-4aec-9c13-cda127b17e2d`, the recorded zone B |
| `ztd-m3-b` uid | `ef71dd81-5629-4f9e-9b10-6adeb3e8298a` |
| Guarded path `https://160.44.12.245` (`verify_public_route.py`, TLS verified against the demo CA, two reset runs) | PASS, `zone-b-preflight-route/execution.json` |
| Workloads | `ztd-connector` (Helm `connector-0.1.0`) and `ztd-token-store` (Helm `token-store-0.3.0`), ServiceAccounts `ztd-connector` and `ztd-token-store`, `automountServiceAccountToken: false`, both ready |
| OpenBao | Helm release `ztd-openbao` (`ztd-openbao-0.2.0`, OpenBao 2.5.4), StatefulSet ServiceAccount `ztd-openbao`, API token mounted (upstream default) |
| Server → API server lane | present: `CiliumNetworkPolicy allow-kube-api-egress` (management plane, `kube-apiserver` entity, 443) |
| `system:auth-delegator` binding for `ztd-mgmt/ztd-openbao` | **absent** (only `kube-system` accounts hold it) |
| Kubernetes auth method in OpenBao | not readable: the only token the zone holds (`ztd-verify`) may not read `sys/auth`; by design no root token exists |

## Why the step stopped

Enabling an auth method and writing roles needs an OpenBao token allowed on `sys/auth/kubernetes`,
`auth/kubernetes/config` and `auth/kubernetes/role/*`. Zone B's root token is revoked by design.
The only approved way to a temporary administrator is the recorded recovery procedure
(`scripts/m3-closeout/openbao_recover.py` on `wt-m3-recovery`); that procedure is reviewed for one
thing, issuing the two scoped tokens (full or `--tokens-only`), and has no step that configures an
auth method. Using its temporary root for anything else would be an unreviewed path, so it was not
used. Two further gaps sit outside OpenBao: the running images predate the Kubernetes-auth client
(an upgrade needs images built from this branch that pass the namespace's admission policy), and
the auth-delegator binding is cluster-scoped.

## Admin action needed (for the project lead to approve and review)

1. **Kubernetes**: bind `system:auth-delegator` to `ztd-mgmt/ztd-openbao` (a `ClusterRoleBinding`,
   what the chart renders with `openbao.server.authDelegator.enabled`). The API lane exists.
2. **OpenBao** (with a reviewed extension of the recovery procedure, or another administrator token):
   - `sys/auth/kubernetes` with `type=kubernetes`;
   - `auth/kubernetes/config`: `kubernetes_host=https://kubernetes.default.svc`;
   - `auth/kubernetes/role/ztd-m3-connector`: `bound_service_account_names=ztd-connector`,
     `bound_service_account_namespaces=ztd-m3-b`, `audience=openbao`,
     `token_policies=ztd-m3-connector`, `token_ttl=1h`, `token_max_ttl=1h`;
   - `auth/kubernetes/role/ztd-m3-token-store`: the same with `ztd-token-store` and
     `token_policies=ztd-m3-token-store`.
   The policies `ztd-m3-connector` and `ztd-m3-token-store` exist and stay as reviewed (equal to the
   scoped tokens' policies). Then revoke the temporary administrator as the procedure does.
3. **Images**: connector and token-store images from this branch, admitted by the `ztd-m3-b`
   admission policy.
4. **Switch, one service at a time** (`helm upgrade --reset-then-reuse-values` with this branch's chart, the new digest and
   `openbao.auth.method=kubernetes`, `openbao.auth.role=ztd-m3-connector` / `ztd-m3-token-store`);
   retry a rollout refused with `ADM-PROVIDER-DOWN`; check `/readyz` and the guarded path
   (`verify_public_route.py`) after each.
5. **Rollback**: `openbao.auth.method=token` on the same release (`helm upgrade --reset-then-reuse-values` or
   `helm rollback`); the token Secrets stay in place until the new mode has run past several
   token lifetimes, and then are revoked by accessor.

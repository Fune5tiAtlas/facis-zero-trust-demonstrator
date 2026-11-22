# Zone B: Kubernetes-auth migration, live step

Date: 21 to 22 November 2026, approved by the project lead ("Approve (Recommended)": extend the
reviewed recovery procedure with a "configure Kubernetes auth" action, add the auth-delegator
binding, then switch both deployments with rollback to token mode).

**Outcome.** The server side is done and verified. The switch of the two deployments **did not
happen**: it needs images built from this branch and signed with the interim Cosign key, which only
the release workflow holds, and running that workflow needs a push, which this task may not do. Both
deployments still run token mode on the scoped tokens (hard ceiling about 28 November, 17:26 UTC),
and the guarded path works.

## Steps

| # | Step | Result | Record |
|---|---|---|---|
| 0 | Read-only preflight (21 Nov): cluster `kube-system` uid `a39ae8ea-…`, `ztd-m3-b` uid `ef71dd81-…`, releases `ztd-connector` (connector-0.1.0) and `ztd-token-store` (token-store-0.3.0), OpenBao 2.5.4, API lane `allow-kube-api-egress` present, no auth-delegator binding | as expected | `zone-b-preflight-route/` |
| 1 | Guarded path before | PASS | `live/route-1-before/execution.json` |
| 2 | `ClusterRoleBinding ztd-m3-openbao-auth-delegator` (`system:auth-delegator` to `ztd-mgmt/ztd-openbao`); `can-i create tokenreviews` as that account: yes | applied | `live/auth-delegator.yaml` |
| 3 | Plan regenerated as for the 21 Nov reissue: `work/status-2026-11-21/openbao-recovery-plan-t6`, ConfigMap resourceVersion 21244340 → 27769872 only, uid and content hash unchanged, enable-patch hash re-recorded; fresh private dir `work/private/m3-zone-b-openbao-20261121-t6` | done | (private) |
| 4 | `openbao_recover.py run --approved-zone-b-recovery --configure-kubernetes-auth` (recovery branch commit `c9a0d336`, self-test PASS): temporary listener setting, restart and unseal, temporary administrator, `auth/kubernetes/` enabled and configured (`https://kubernetes.default.svc`, server's own CA and token), roles `ztd-m3-connector` (`ztd-connector`) and `ztd-m3-token-store` (`ztd-token-store`), namespace `ztd-m3-b`, audience `openbao`, existing policies, ttl 1 h; real logins with minted ServiceAccount tokens give exactly `default` + the role's policy, wrong audience and the other account refused; administrator revoked and refused; ConfigMap restored, restart and unseal, logins verified again | PASS | `live/recovery/recovery.json` |
| 5 | Workloads after (still token mode): both ready; guarded path | PASS | `live/route-2-after-auth-config/execution.json` |
| 6 | Switch token store, then connector, to `openbao.auth.method=kubernetes` | **not done**: no admissible image (above) | |

## To finish (needs the release workflow)

1. Publish signed connector and token-store images from this branch (release workflow, interim
   Cosign key; the `ztd-m3-b` admission policy checks that key and the repository).
2. Token store: `helm upgrade ztd-token-store <this branch>/deployment/helm/token-store -n ztd-m3-b
   --reset-then-reuse-values --set image.digest=<new> --set openbao.auth.method=kubernetes
   --set openbao.auth.role=ztd-m3-token-store --set 'runtime.credentialKeys={fixture.pem,store-client-secret}'`;
   retry a rollout refused with `ADM-PROVIDER-DOWN`; check `/readyz` and the guarded path.
3. Connector: the same with `openbao.auth.role=ztd-m3-connector` (its chart drops the token key from
   its mount in this mode).
4. Rollback for either: `--set openbao.auth.method=token` (or `helm rollback`); the token Secrets
   stay until the new mode has run past several token lifetimes, then the scoped tokens are revoked
   by accessor.

Rollback of what was done (not needed; the workloads ignore it while in token mode): the recovery
procedure with a temporary administrator to disable `auth/kubernetes/`, and
`kubectl delete clusterrolebinding ztd-m3-openbao-auth-delegator`.

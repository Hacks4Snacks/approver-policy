<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>
<p align="center">
  <a href="https://godoc.org/github.com/cert-manager/approver-policy"><img src="https://godoc.org/github.com/cert-manager/approver-policy?status.svg" alt="approver-policy godoc"></a>
  <a href="https://goreportcard.com/report/github.com/cert-manager/approver-policy"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/cert-manager/approver-policy" /></a>
  <a href="https://artifacthub.io/packages/search?repo=cert-manager"><img alt="Artifact Hub" src="https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/cert-manager" /></a>
  <a href="https://github.com/cert-manager/approver-policy/actions/workflows/govulncheck.yaml"><img alt="govulncheck" src="https://github.com/cert-manager/approver-policy/actions/workflows/govulncheck.yaml/badge.svg" /></a>
</p>

# approver-policy

approver-policy is a [cert-manager](https://cert-manager.io) approver that is
responsible for [Approving or Denying
CertificateRequests](https://cert-manager.io/docs/concepts/certificaterequest/#approval).

approver-policy exposes the CertificateRequestPolicy resource which
administrators use to define policy over what, who, and how certificates are
signed by cert-manager.

---

Please follow the documentation at
[cert-manager.io](https://cert-manager.io/docs/usage/approver-policy/) for
installing and using approver-policy.

## Policy Set Proposal

This branch includes an opt-in `CertificateRequestPolicySet` prototype for
coordinating policy membership and readiness. See the
[design proposal](design/20261008-policy-sets.md) for the API, evaluation rules,
examples, and upgrade limitations. This is not a released upstream feature.
Enable it with `app.enablePolicySets: true` in Helm or `--enable-policy-sets=true`.
It defaults off; disabling it leaves policies with `policySetRef` inactive.
Follow the [staged activation procedure](design/20261008-policy-sets.md#first-activation):
upgrade every replica with the gate off, enable it across every replica, then
apply opt-in configuration. Mixed-version compatibility requires release-level
validation; the prototype's local tests do not certify older released images.

## Makefile modules

This project uses [Makefile modules](https://github.com/cert-manager/makefile-modules), see the README there for more information.
A summary of the available make targets can be found by running `make help`.

## Release Process

The release process is documented in [RELEASE.md](RELEASE.md).

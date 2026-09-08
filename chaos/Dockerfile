# One shared image for every service in the sandbox (remote, all three
# actors, all three chaos agents, the verifier) — differentiated purely by
# `command:`/environment in docker-compose.yml, not by separate images.
# Fewer moving parts to get wrong when nobody can run this until the user
# tries it (see specs/chaotests/01-sandbox.md's Status note).
#
# Builds securegit from the *local working tree* (not a published version),
# so the sandbox always exercises exactly the code currently checked out —
# specs/chaotests/01-sandbox.md's Orchestration section requires this.
#
# Build context is the repository root (see docker-compose.yml), not this
# directory, because this stage needs the whole packages/ workspace and the
# root package.json from there.
#
# Since the extraction into @trinoris/securelib (docs/securegit/01-architecture.md): this is
# now a two-package npm workspace, not one flat package. `npm ci` at the
# root installs and symlinks both; `npm run build --workspaces` builds
# both. The runtime stage below copies both packages' `dist/` output —
# securegit's under /app/dist (unchanged path, so /app/dist/bin/securegit.js
# still works exactly as before), and securelib's under
# /app/node_modules/@trinoris/securelib (mirroring where Node's own module
# resolution — and securegit's own compiled `@trinoris/securelib/*`
# imports — expect to find it at runtime, same as the workspace symlink
# npm itself creates during the build stage).

FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* tsconfig.base.json ./
COPY packages/securelib/package.json packages/securelib/tsconfig.json packages/securelib/tsconfig.build.json packages/securelib/
COPY packages/securegit/package.json packages/securegit/tsconfig.json packages/securegit/tsconfig.build.json packages/securegit/
RUN npm ci
COPY packages/securelib/src packages/securelib/src
COPY packages/securegit/src packages/securegit/src
# Order matters: securegit's own build (typecheck + declaration resolution
# of `@trinoris/securelib/*` imports) needs securelib's compiled dist/
# already present — `--workspaces` alone does not guarantee build order.
RUN npm run build --workspace=packages/securelib \
    && npm run build --workspace=packages/securegit

FROM node:20-alpine
# git-daemon is a separate Alpine package from git itself — Alpine splits
# `git daemon` out (confirmed via `apk info -L git`, which does not list
# it; `git-daemon` does). Without it `remote`'s `git daemon` invocation
# fails immediately with "git: 'daemon' is not a git command" and the
# service never actually listens on :9418 — every other service's clone/
# fetch/push then times out waiting for a remote that was never there.
# openssh-keygen is likewise a separate package from git — needed once
# commit signing entered the sandbox (specs/chaotests/03-orchestrator.md's
# "Since then" note): `identity.ts`'s generateSigningKeyPair() shells out
# to `ssh-keygen` directly, and git's own `gpg.format=ssh` signing
# (`commit.gpgsign=true`) invokes `ssh-keygen -Y sign` internally at commit
# time too — without this package, both fail with ENOENT (confirmed by a
# real run: every collaborator's bootstrap crashed on
# `identity init --generate-signing-key` until this was added).
RUN apk add --no-cache git git-daemon openssh-keygen bash coreutils iptables iproute2 procps
WORKDIR /app
COPY --from=build /app/packages/securegit/dist ./dist
COPY --from=build /app/packages/securegit/package.json ./package.json
COPY --from=build /app/packages/securelib/dist ./node_modules/@trinoris/securelib/dist
COPY --from=build /app/packages/securelib/package.json ./node_modules/@trinoris/securelib/package.json
RUN printf '#!/bin/sh\nexec node /app/dist/bin/securegit.js "$@"\n' > /usr/local/bin/securegit \
    && chmod +x /usr/local/bin/securegit

COPY chaos/lib /chaos/lib
COPY chaos/actors /chaos/actors
COPY chaos/agents /chaos/agents
COPY chaos/remote /chaos/remote
COPY chaos/verifier /chaos/verifier

# Every role sets HOME explicitly in docker-compose.yml — this default only
# covers ad-hoc `docker run`/debugging.
ENV HOME=/home/sandbox
RUN mkdir -p /home/sandbox

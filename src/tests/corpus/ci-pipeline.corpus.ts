import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "GATE_STEP_ABSENT",
    check: "ci-pipeline",
    positive: {
      file: ".github/workflows/build.yml",
      content: `name: Build\non:\n  push:\n    branches: [main]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm ci\n      - run: npm run build\n`
    },
    negative: {
      file: ".github/workflows/build.yml",
      content: `name: Build\non:\n  pull_request:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm ci\n      - run: npm run ci:pr-gate\n`
    },
    note: "Negative adds the actual gate invocation step (npm run ci:pr-gate), the exact remediation the rule requests, so at least one workflow is found to invoke the gate."
  },
  {
    ruleId: "GATE_STEP_DISABLED",
    check: "ci-pipeline",
    positive: {
      file: ".github/workflows/ci.yml",
      content: `name: CI\non:\n  pull_request:\njobs:\n  gate:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm ci\n      # - run: npm run ci:pr-gate\n      - run: npm test\n`
    },
    negative: {
      file: ".github/workflows/ci.yml",
      content: `name: CI\non:\n  pull_request:\njobs:\n  gate:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm ci\n      - run: npm run ci:pr-gate\n      - run: npm test\n`
    },
    note: "Negative uncomments the gate step so the line is active (not prefixed with #), the exact fix in requiredActions ('Uncomment or re-enable')."
  },
  {
    ruleId: "GATE_WORKFLOW_SELF_MODIFICATION",
    check: "ci-pipeline",
    positive: {
      file: ".github/workflows/security-gate.yml",
      content: `name: Security Gate\non:\n  pull_request:\njobs:\n  gate:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm ci\n      # - run: npm run ci:pr-gate\n`
    },
    negative: {
      file: ".github/workflows/security-gate.yml",
      content: `name: Security Gate\non:\n  pull_request:\njobs:\n  gate:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm ci\n      - run: npm run ci:pr-gate\n`
    },
    note: "Same file (security-gate.yml, so changedFiles still flags it as the gate workflow being touched) but the gate invocation stays active/uncommented, so gateDisabledFile is never set and the self-modification finding cannot fire."
  },
  {
    ruleId: "CI_WORKFLOW_INJECTION",
    check: "ci-pipeline",
    positive: {
      file: ".github/workflows/comment.yml",
      content: `name: Comment\non:\n  issues:\n    types: [opened]\njobs:\n  comment:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Post comment\n        run: |\n          echo "Title: \${{ github.event.issue.title }}"\n`
    },
    negative: {
      file: ".github/workflows/comment.yml",
      content: `name: Comment\non:\n  issues:\n    types: [opened]\njobs:\n  comment:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Set title env\n        env:\n          TITLE: \${{ github.event.issue.title }}\n        run: |\n          echo "Title: $TITLE"\n`
    },
    note: "Negative passes the untrusted value through env: (the rule's own recommended fix) and references $TITLE in the shell; the injection token no longer sits within 5 lines AFTER (i.e. preceded by) a run: line, since run: now follows env: rather than preceding the interpolation."
  },
  {
    ruleId: "CI_CACHE_POISONING",
    check: "ci-pipeline",
    positive: {
      file: ".github/workflows/cache.yml",
      content: `name: Build\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/cache@v3\n        with:\n          path: ~/.npm\n          key: npm-\${{ github.head_ref }}-\${{ hashFiles('**/package-lock.json') }}\n`
    },
    negative: {
      file: ".github/workflows/cache.yml",
      content: `name: Build\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/cache@v3\n        with:\n          path: ~/.npm\n          key: npm-\${{ github.ref }}-\${{ hashFiles('**/package-lock.json') }}\n`
    },
    note: "Negative keys the cache on github.ref (a trusted, non-attacker-controlled value) instead of github.head_ref, exactly as requiredActions recommends."
  },
  {
    ruleId: "CI_ARTIFACT_NO_VERIFY",
    check: "ci-pipeline",
    positive: {
      file: ".github/workflows/deploy.yml",
      content: `name: Deploy\non: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/download-artifact@v4\n        with:\n          name: build-output\n      - run: ./build-output/install.sh\n`
    },
    negative: {
      file: ".github/workflows/deploy.yml",
      content: `name: Deploy\non: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/download-artifact@v4\n        with:\n          name: build-output\n      - name: Verify artifact checksum\n        run: echo "expectedsha256sum  build-output/app.tar.gz" | sha256sum -c -\n      - run: ./build-output/install.sh\n`
    },
    note: "Negative adds a sha256sum verification step within the 10-line lookahead window after the download-artifact step, exactly the remediation requested."
  },
  {
    ruleId: "CI_GITHUB_TOKEN_WRITE_ALL",
    check: "ci-pipeline",
    positive: {
      file: ".github/workflows/pr.yml",
      content: `name: PR\non:\n  pull_request:\npermissions:\n  contents: write\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n`
    },
    negative: {
      file: ".github/workflows/pr.yml",
      content: `name: PR\non:\n  pull_request:\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n`
    },
    note: "Negative scopes permissions to contents: read instead of write, the minimal-scope fix requiredActions recommends, on the identical pull_request-triggered workflow."
  },
  {
    ruleId: "CI_FORK_SECRET_EXPOSURE",
    check: "ci-pipeline",
    positive: {
      file: ".github/workflows/fork.yml",
      content: `name: Fork PR\non:\n  pull_request:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Use secret\n        env:\n          API_KEY: \${{ secrets.API_KEY }}\n        run: ./build.sh\n`
    },
    negative: {
      file: ".github/workflows/fork.yml",
      content: `name: Fork PR\non:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Use secret\n        env:\n          API_KEY: \${{ secrets.API_KEY }}\n        run: ./deploy.sh\n`
    },
    note: "Negative moves the exact same secret-dependent step to a pull_request_target-triggered workflow as requiredActions instructs; the rule's regex only matches a literal 'pull_request:' trigger line, which pull_request_target: does not satisfy."
  },
  {
    ruleId: "CI_NPM_MISSING_IGNORE_SCRIPTS",
    check: "ci-pipeline",
    positive: {
      file: ".github/workflows/install.yml",
      content: `name: Install\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm ci\n      - run: npm run build\n`
    },
    negative: {
      file: ".github/workflows/install.yml",
      content: `name: Install\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm ci --ignore-scripts\n      - run: npm run build\n`
    },
    note: "Negative appends --ignore-scripts to the npm ci invocation on the same line, defeating the rule's negative lookahead exactly as requiredActions recommends."
  },
  {
    ruleId: "CI_WORKFLOW_LEVEL_SECRET_ENV",
    check: "ci-pipeline",
    positive: {
      file: ".github/workflows/deploy2.yml",
      content: `name: CI\non: push\nenv:\n  DEPLOY_TOKEN: \${{ secrets.DEPLOY_TOKEN }}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n`
    },
    negative: {
      file: ".github/workflows/deploy2.yml",
      content: `name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Deploy\n        env:\n          DEPLOY_TOKEN: \${{ secrets.DEPLOY_TOKEN }}\n        run: ./deploy.sh\n`
    },
    note: "Negative moves the secret from a workflow-level env: block (indent 0, in scope) into the one step's own env: (indent 8, > the rule's <=4 threshold for workflow/job-level blocks), exactly as requiredActions instructs."
  },
  {
    ruleId: "CI_SECRET_IN_STEP_OUTPUT",
    check: "ci-pipeline",
    positive: {
      file: ".github/workflows/export.yml",
      content: `name: Export\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Export token\n        run: |\n          echo "token=\${{ secrets.API_TOKEN }}" >> $GITHUB_OUTPUT\n`
    },
    negative: {
      file: ".github/workflows/export.yml",
      content: `name: Export\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Export status\n        run: |\n          echo "status=success" >> $GITHUB_OUTPUT\n`
    },
    note: "Negative writes a non-sensitive derived value to $GITHUB_OUTPUT instead of the raw secret, exactly the 'derive a non-sensitive value instead' remediation."
  },
  {
    ruleId: "CI_SECRET_TO_THIRD_PARTY_ACTION",
    check: "ci-pipeline",
    positive: {
      file: ".github/workflows/thirdparty.yml",
      content: `name: Deploy\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Deploy via third-party action\n        uses: some-vendor/deploy-action@v2\n        with:\n          token: \${{ secrets.DEPLOY_TOKEN }}\n`
    },
    negative: {
      file: ".github/workflows/thirdparty.yml",
      content: `name: Deploy\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Checkout with token\n        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n        with:\n          token: \${{ secrets.DEPLOY_TOKEN }}\n`
    },
    note: "Negative passes the identical secret input to a first-party actions/* action (SHA-pinned) instead of a third-party owner; checkSecretToThirdPartyAction explicitly skips owner === 'actions', matching requiredActions' 'prefer official first-party actions'."
  },
  {
    ruleId: "CI_SELF_HOSTED_PR_TRIGGER",
    check: "ci-pipeline",
    positive: {
      file: ".github/workflows/selfhosted-pr.yml",
      content: `name: PR Build\non:\n  pull_request:\njobs:\n  build:\n    runs-on: self-hosted\n    steps:\n      - run: npm test\n`
    },
    negative: {
      file: ".github/workflows/selfhosted-pr.yml",
      content: `name: PR Build\non:\n  pull_request:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n`
    },
    note: "Negative switches to a GitHub-hosted runner on the identical pull_request-triggered workflow, exactly as requiredActions recommends ('Use GitHub-hosted runners for ... untrusted code paths')."
  },
  {
    ruleId: "CI_UNPINNED_ACTION",
    check: "ci-pipeline",
    positive: {
      file: ".github/workflows/actions.yml",
      content: `name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm test\n`
    },
    negative: {
      file: ".github/workflows/actions.yml",
      content: `name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n      - run: npm test\n`
    },
    note: "Negative pins the same action to a full 40-character commit SHA instead of the mutable @v4 tag, exactly as requiredActions recommends."
  },
  {
    ruleId: "CI_PWNTARGET_SHA",
    check: "ci-pipeline",
    positive: {
      file: ".github/workflows/pwn.yml",
      content: `name: Build PR\non:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}\n`
    },
    negative: {
      file: ".github/workflows/pwn.yml",
      content: `name: Build PR\non:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n`
    },
    note: "Negative keeps pull_request_target but checks out the default trusted base ref instead of interpolating the attacker-controlled github.event.pull_request.head.sha, closing the pwn-request vector without changing the trigger."
  },
  {
    ruleId: "CI_SECRET_ECHO",
    check: "ci-pipeline",
    positive: {
      file: ".github/workflows/echo.yml",
      content: `name: Notify\non: push\njobs:\n  notify:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \${{ secrets.API_KEY }}\n`
    },
    negative: {
      file: ".github/workflows/echo.yml",
      content: `name: Notify\non: push\njobs:\n  notify:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Call API\n        env:\n          API_KEY: \${{ secrets.API_KEY }}\n        run: |\n          curl -H "Authorization: Bearer $API_KEY" https://api.example.com\n`
    },
    note: "Negative passes the secret through env: and consumes it via $API_KEY in curl instead of echoing it directly, exactly as requiredActions recommends ('never echo them')."
  },
  {
    ruleId: "CI_NO_PERMISSIONS",
    check: "ci-pipeline",
    positive: {
      file: ".github/workflows/perms.yml",
      content: `name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n`
    },
    negative: {
      file: ".github/workflows/perms.yml",
      content: `name: CI\non: push\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n`
    },
    note: "Negative adds the explicit top-level permissions: block requiredActions recommends (minimal contents: read), which the rule's /^permissions:/m check now finds."
  },
  {
    ruleId: "CI_SELF_HOSTED_RUNNER",
    check: "ci-pipeline",
    positive: {
      file: ".github/workflows/runner.yml",
      content: `name: CI\non: push\njobs:\n  build:\n    runs-on: self-hosted\n    steps:\n      - run: npm test\n`
    },
    negative: {
      file: ".github/workflows/runner.yml",
      content: `name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n`
    },
    note: "Negative uses a GitHub-hosted runner instead of self-hosted, exactly as requiredActions recommends."
  }
];

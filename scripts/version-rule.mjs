// Shared version-rule logic for the odometer versioning scheme.
//
// Rule: a bump increases the version by 0.0.1 (patch + 1). Each of the minor
// and patch segments is a single decimal digit (0-9); reaching 10 carries into
// the next-higher segment and resets to 0. The major segment is the top of the
// odometer and is never capped.
//
//   1.0.9  -> bump -> 1.0.10 -> normalized -> 1.1.0
//   1.9.9  -> bump -> 1.9.10 -> normalized -> 2.0.0
//
// A version is VALID under this rule iff minor < 10 and patch < 10.

const SEMVER = /^(\d+)\.(\d+)\.(\d+)$/;

export function parse(version) {
  const m = SEMVER.exec(String(version).trim());
  if (!m) {
    throw new Error(`Not a plain MAJOR.MINOR.PATCH version: "${version}"`);
  }
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) };
}

export function format({ major, minor, patch }) {
  return `${major}.${minor}.${patch}`;
}

// Returns null when valid, or a human-readable reason when the version violates
// the odometer rule.
export function violation(version) {
  let v;
  try {
    v = parse(version);
  } catch (err) {
    return err.message;
  }
  if (v.minor > 9) {
    return `minor segment is ${v.minor} (must be 0-9; should have carried into major)`;
  }
  if (v.patch > 9) {
    return `patch segment is ${v.patch} (must be 0-9; should have carried into minor)`;
  }
  return null;
}

export function isValid(version) {
  return violation(version) === null;
}

// Applies one bump (+0.0.1) with carry-at-10 normalization.
export function bump(version) {
  const reason = violation(version);
  if (reason) {
    throw new Error(`Cannot bump invalid version "${version}": ${reason}`);
  }
  let { major, minor, patch } = parse(version);
  patch += 1;
  if (patch >= 10) {
    patch = 0;
    minor += 1;
  }
  if (minor >= 10) {
    minor = 0;
    major += 1;
  }
  return format({ major, minor, patch });
}

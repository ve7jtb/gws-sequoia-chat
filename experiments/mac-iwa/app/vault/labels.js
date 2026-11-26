/** Format display text only: persisted friendly names and bindings stay untouched. */
export function unlockMethodLabel(method) {
  let name = method.name;
  const serial = String(method.binding?.serial || '');
  // Match a complete numeric serial, never a fragment of a different device ID.
  if (/^\d+$/.test(serial)) {
    const existing = new RegExp(`(?:SN#\\s*)?(?<!\\d)${serial}(?!\\d)`, 'i');
    name = existing.test(name)
      ? name.replace(existing, `SN# ${serial}`)
      : `${name} · SN# ${serial}`;
  }
  return `${name} · ${method.type.toUpperCase()}`;
}

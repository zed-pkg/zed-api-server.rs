#!/usr/bin/env python3
"""Prepare the bounded canonical-core cutover for the full Rust gate."""

from pathlib import Path

# Legacy SQLite fixtures intentionally exercise only the compatibility
# transaction. Make their lack of canonical contexts explicit at every call
# site so production constructors remain fail-closed.
for relative in (
    "src/routes/audit.rs",
    "src/routes/orgs.rs",
    "src/routes/publish.rs",
    "src/routes/yank.rs",
):
    path = Path(relative)
    text = path.read_text()
    old = "            db,\n            store:"
    if text.count(old) != 1:
        raise SystemExit(f"{path}: expected exactly one legacy AppState fixture")
    path.write_text(
        text.replace(
            old,
            "            db,\n"
            "            registry_read: None,\n"
            "            registry_write: None,\n"
            "            store:",
            1,
        )
    )

# The verified subject already lives on SessionIdentity. Remove the redundant
# non-test accessor rather than suppressing dead-code warnings, and keep the
# unit test pinned to the canonical field.
auth = Path("src/auth.rs")
text = auth.read_text()
old_impl = '''
impl AccountIdentity {
    pub fn subject(&self) -> Uuid {
        self.session.subject
    }
}
'''
if text.count(old_impl) != 1:
    raise SystemExit("src/auth.rs: expected one redundant AccountIdentity accessor")
text = text.replace(old_impl, "\n", 1)
old_assertion = "        assert_eq!(identity.subject(), SUBJECT.parse::<Uuid>().unwrap());"
new_assertion = "        assert_eq!(identity.session.subject, SUBJECT.parse::<Uuid>().unwrap());"
if text.count(old_assertion) != 1:
    raise SystemExit("src/auth.rs: expected one subject accessor assertion")
auth.write_text(text.replace(old_assertion, new_assertion, 1))

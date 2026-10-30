# Wrong-product comparator captures

These two VSIX files identify `amazonwebservices.aws-toolkit-vscode`, not
`amazonwebservices.amazon-q-vscode`. They were previously used as the clean and
remediated comparators for the captured Amazon Q 1.84.0 attack.

On 2026-09-10 they were moved here, together with their unchanged capture sidecars,
to preserve the evidence of that mismatch. They are reference material, not
before/after releases of the affected product. No bytes were deleted or modified.

The sample manifest now selects official Amazon Q 1.83.0 and 1.85.0 distributions
whose embedded package and VSIX identities match the affected extension.

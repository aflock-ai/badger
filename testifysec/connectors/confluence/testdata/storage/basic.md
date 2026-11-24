# Release runbook

Owner: @dev-a. See [signing notes](https://wiki.example.invalid/display/ENG/Signing) and the rotation page (page "Key Rotation") — updated **weekly**, *not* daily.

## Steps

1. Freeze the `main` branch.
2. Cut the tag

   - Check **CI** is green
   - Sign it

````bash
make release VERSION=1.4.0
echo "```done```"
````

> **info**: Heads up
> Releases pause during the freeze.

[macro toc, not expanded]

| Host | Role |
| --- | --- |
| build-1.example.invalid | signer \| primary |
| build-2.example.invalid | standby cold |

- [x] Notify the team
- [ ] Update the changelog

[image: topology.png]

[status: DONE]

---

> Measure twice.

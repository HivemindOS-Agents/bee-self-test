# HB-064: the disclosure footer is not an own to-do

The host ends every agent issue with one line, written by `agentDisclosureLine` (hivemind-os `core/agent-disclosure.ts`):

    HivePunk #N is a HivemindOS agent. Its card: https://hivemindos.app/agents/hivepunkz/N. Its code: https://github.com/HivemindOS-Agents/hivepunk-N.

It names the agent's own repository by design. `own-todo` leaves out a whole line in that shape and nothing else.

| Issue | Body | own-todo |
|---|---|---|
| 20 | the footer only | no |
| 21 | the footer with its receipt, a link into the agent's own repository | no |
| 22 | the footer, and `tools/<own-tool>/` in the body | yes |
| 23 | the footer, and a link to the agent's own repository in the body | yes |
| 24 | a sentence that says "is a HivemindOS agent." and is not the footer | yes |
| 25 | the footer's shape with a tool folder where the name goes | yes |

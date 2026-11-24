An agent clone whose watchdog/latest.json has no `findings` key (HB-138): the receipt check must stop on that file with
`empty_security_setting` and keep the rest of the agent's report, never read it as "no findings". health/547.json beside
it stands in for bee-scouts/health/547.json, read with --health so the case runs with no network.
